#include <test/test.h>
#include <test/mock.h>
#include <linux/platform_device_mock.h>
#include <linux/i2c.h>
#include <linux/i2c-mock.h>
#include <linux/interrupt.h>
#include <asm/io-mock.h>
#include "i2c-aspeed.h"
#include "i2c-aspeed-fake.h"

#define ASPEED_I2C_MAX_BASE_DIVISOR		(1 << ASPEED_I2CD_TIME_BASE_DIVISOR_MASK)
#define ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK	GENMASK(2, 0)
#define ASPEED_I2C_24XX_CLK_HIGH_LOW_MAX	((ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK + 1) * 2)
#define ASPEED_I2C_24XX_MAX_DIVISOR		(ASPEED_I2C_MAX_BASE_DIVISOR * ASPEED_I2C_24XX_CLK_HIGH_LOW_MAX)
#define ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK	GENMASK(3, 0)
#define ASPEED_I2C_25XX_CLK_HIGH_LOW_MAX	((ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK + 1) * 2)
#define ASPEED_I2C_25XX_MAX_DIVISOR		(ASPEED_I2C_MAX_BASE_DIVISOR * ASPEED_I2C_25XX_CLK_HIGH_LOW_MAX)

struct aspeed_i2c_test {
	struct test *test;
	struct platform_device *pdev;
	struct i2c_adapter *adap;
	irq_handler_t irq_handler;
	void *irq_ctx;
	struct work_struct call_irq_handler;
	struct i2c_client *client;
	struct aspeed_i2c_fake *i2c_fake;
};

DEFINE_FUNCTION_MOCK(devm_ioremap_resource,
		     RETURNS(void __iomem *),
		     PARAMS(struct device *, struct resource *));
DEFINE_FUNCTION_MOCK(__devm_reset_control_get,
		     RETURNS(struct reset_control *),
		     PARAMS(struct device *, const char *, int, bool, bool));
DEFINE_FUNCTION_MOCK(reset_control_deassert,
		     RETURNS(int),
		     PARAMS(struct reset_control *));
DEFINE_FUNCTION_MOCK(devm_request_threaded_irq,
		     RETURNS(int),
		     PARAMS(struct device *,
			    unsigned int,
			    irq_handler_t,
			    irq_handler_t,
			    unsigned long,
			    const char *,
			    void *));

static void call_irq_handler(struct work_struct *work)
{
	struct aspeed_i2c_test *ctx = container_of(work,
						   struct aspeed_i2c_test,
						   call_irq_handler);

	EXPECT_EQ(ctx->test, IRQ_HANDLED, ctx->irq_handler(0, ctx->irq_ctx));
}

static void *schedule_irq_handler_call(struct test *test, const void *params[], int len)
{
	struct aspeed_i2c_test *ctx = test->priv;

	ASSERT_TRUE(ctx->test, schedule_work(&ctx->call_irq_handler));

	return ctx;
}

static void schedule_irq_handler_call_new(struct test *test)
{
	struct aspeed_i2c_test *ctx = test->priv;

	ASSERT_TRUE(ctx->test, schedule_work(&ctx->call_irq_handler));
}

/* Adds expectations which are common to many test cases which test conditions
 * that eventually lead to a transfer (e.g after performing some recovery steps etc).
 */
static void aspeed_i2c_master_xfer_start_transaction(struct test *test,
                                                     struct mock_expectation *precondition)
{
        struct aspeed_i2c_test *ctx = test->priv;
        struct i2c_client *client = ctx->client;
        struct mock_expectation *write_client_addr,
            *write_start_cmd, *slave_response, *ack_slave_response,
            *write_first_byte, *first_byte_tx_cmd, *first_byte_sent,
            *ack_first_byte_tx, *write_second_byte, *second_byte_tx_cmd,
            *second_byte_sent, *ack_second_byte_tx, *stop_tx, *bus_stopped,
            *write_bus_stopped;

        u8 msg[] = {0xae, 0x00};

        /* Start transaction. */
        write_client_addr = EXPECT_CALL(writel(
            u32_eq(test, client->addr << 1),
            u32_eq(test, ASPEED_I2C_BYTE_BUF_REG)));
        /*
         * After the above expectation is hit the thread on which
         * i2c_master_send is called will be put to sleep. However, we scheduled
         * a worker to call the IRQ handler which should execute next.
         */
        write_start_cmd = ActionOnMatch(
            EXPECT_CALL(writel(u32_eq(test,
                                      ASPEED_I2CD_M_START_CMD |
                                      ASPEED_I2CD_M_TX_CMD),
                               u32_eq(test, ASPEED_I2C_CMD_REG))),
            invoke(test, schedule_irq_handler_call));

        /* Tell the handler a slave responded. */
        slave_response = EXPECT_CALL(readl(u32_eq(test,
                                                  ASPEED_I2C_INTR_STS_REG)));
        Returns(slave_response,
                u32_return(test, ASPEED_I2CD_INTR_TX_ACK));

        ack_slave_response = EXPECT_CALL(writel(
            u32_eq(test, ASPEED_I2CD_INTR_TX_ACK),
            u32_eq(test, ASPEED_I2C_INTR_STS_REG)));

        /* Expect the first byte. */
        write_first_byte = EXPECT_CALL(writel(
            u32_eq(test, msg[0]), u32_eq(test, ASPEED_I2C_BYTE_BUF_REG)));
        /* Master should continue to wait to send another byte. */
        first_byte_tx_cmd = ActionOnMatch(
            EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_M_TX_CMD),
                               u32_eq(test, ASPEED_I2C_CMD_REG))),
            invoke(test, schedule_irq_handler_call));

        /* Tell the handler the first byte was received. */
        first_byte_sent = EXPECT_CALL(readl(u32_eq(test,
                                                   ASPEED_I2C_INTR_STS_REG)));
        Returns(first_byte_sent,
                u32_return(test, ASPEED_I2CD_INTR_TX_ACK));

        ack_first_byte_tx = EXPECT_CALL(writel(
            u32_eq(test, ASPEED_I2CD_INTR_TX_ACK),
            u32_eq(test, ASPEED_I2C_INTR_STS_REG)));

        /* Expect the second byte. */
        write_second_byte = EXPECT_CALL(writel(
            u32_eq(test, msg[1]),
            u32_eq(test, ASPEED_I2C_BYTE_BUF_REG)));

        /* Master should continue to wait to receive ACK and STOP bus. */
        second_byte_tx_cmd = ActionOnMatch(
            EXPECT_CALL(writel(
                u32_eq(test, ASPEED_I2CD_M_TX_CMD),
                u32_eq(test, ASPEED_I2C_CMD_REG))),
            invoke(test, schedule_irq_handler_call));

        /* Tell the handler the second byte was received. */
        second_byte_sent = EXPECT_CALL(readl(u32_eq(test,
                                                    ASPEED_I2C_INTR_STS_REG)));
        Returns(second_byte_sent,
                u32_return(test, ASPEED_I2CD_INTR_TX_ACK));

        ack_second_byte_tx = EXPECT_CALL(
            writel(u32_eq(test, ASPEED_I2CD_INTR_TX_ACK),
                   u32_eq(test, ASPEED_I2C_INTR_STS_REG)));

        /* Expect a request to STOP the bus. */
        /* Master should continue to wait to receive ACK and STOP bus. */
        stop_tx = ActionOnMatch(
            EXPECT_CALL(
                writel(u32_eq(test, ASPEED_I2CD_M_STOP_CMD),
                       u32_eq(test, ASPEED_I2C_CMD_REG))),
            invoke(test, schedule_irq_handler_call));

        /* Tell the handler the bus has been stopped. */
        bus_stopped = EXPECT_CALL(readl(
            u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
        Returns(bus_stopped,
                u32_return(test, ASPEED_I2CD_INTR_NORMAL_STOP));

        write_bus_stopped = EXPECT_CALL(
            writel(u32_eq(test, ASPEED_I2CD_INTR_NORMAL_STOP),
                   u32_eq(test, ASPEED_I2C_INTR_STS_REG)));

        InSequence(test, precondition, write_client_addr, write_start_cmd,
                   slave_response, ack_slave_response, write_first_byte,
                   first_byte_tx_cmd, first_byte_sent, ack_first_byte_tx,
                   write_second_byte, second_byte_tx_cmd, second_byte_sent,
                   ack_second_byte_tx, stop_tx, bus_stopped, write_bus_stopped);

        EXPECT_EQ(test,
                  ARRAY_SIZE(msg),
                  i2c_master_send(client, msg, ARRAY_SIZE(msg)));
}

static void aspeed_i2c_master_xfer_test_basic(struct test *test)
{
        struct aspeed_i2c_test *ctx = test->priv;
	struct aspeed_i2c_fake *i2c_fake = ctx->i2c_fake;
        struct i2c_client *client = ctx->client;
        u8 msg[] = {0xae, 0x00};
	int i;

        ASSERT_EQ(test,
                  ARRAY_SIZE(msg),
                  i2c_master_send(client, msg, ARRAY_SIZE(msg)));
	ASSERT_EQ(test, i2c_fake->msgs_count, 1);
	EXPECT_EQ(test, client->addr, i2c_fake->msgs->addr);
	EXPECT_EQ(test, i2c_fake->msgs->len, ARRAY_SIZE(msg));
	for (i = 0; i < ARRAY_SIZE(msg); i++)
		EXPECT_EQ(test, i2c_fake->msgs->buf[i], msg[i]);
}

static void aspeed_i2c_master_xfer_test_idle_bus(struct test *test)
{
        struct mock_expectation *read_cmd_reg_bus_busy, *read_cmd_reg_bus_recovery;

        read_cmd_reg_bus_busy = Returns(EXPECT_CALL(readl(u32_eq(test,
                                                                 ASPEED_I2C_CMD_REG))),
                                        u32_return(test, ASPEED_I2CD_BUS_BUSY_STS));
        /* Read command registers which has both the SDA_LINE_STS and
         * SCL_LINE_STS bits set, meaning the bus is idle and no recovery
         * is not necessary */
        read_cmd_reg_bus_recovery = Returns(EXPECT_CALL(readl(u32_eq(test,
                                                                     ASPEED_I2C_CMD_REG))),
                                            u32_return(test, ASPEED_I2CD_SDA_LINE_STS | ASPEED_I2CD_SCL_LINE_STS));

        InSequence(test, read_cmd_reg_bus_busy, read_cmd_reg_bus_recovery);

        aspeed_i2c_master_xfer_start_transaction(test, /*precondition=*/read_cmd_reg_bus_busy);
}

static void aspeed_i2c_master_xfer_test_recover_bus_reset(struct test *test)
{
        /* Expectation set during the recovery phase. */
        struct mock_expectation *read_cmd_reg_bus_busy, *read_cmd_reg_sda_line_set,
            *write_stop_cmd, *disable_intr, *ack_all_intr, *disable_aspeed,
            *read_clk_reg_value, *write_clk_reg_value, *write_no_timeout_ctrl,
            *read_func_ctrl_reg, *enable_master_mode, *enable_interrupts;

        /* Read command register and return state that indicates the bus to be busy */
        read_cmd_reg_bus_busy = Returns(EXPECT_CALL(readl(u32_eq(test,
                                                                 ASPEED_I2C_CMD_REG))),
                                        u32_return(test, ASPEED_I2CD_BUS_BUSY_STS));
        /* Read command register and only set the SDA_LINE to trigger bus recovery */
        read_cmd_reg_sda_line_set = Returns(EXPECT_CALL(readl(u32_eq(test,
                                                                     ASPEED_I2C_CMD_REG))),
                                            u32_return(test, ASPEED_I2CD_SDA_LINE_STS));
        /* Stop the bus */
        write_stop_cmd = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_M_STOP_CMD),
                                            u32_eq(test, ASPEED_I2C_CMD_REG)));

        /* Disable all interrupts */
        disable_intr = EXPECT_CALL(writel(u32_eq(test, 0),
                                          u32_eq(test, ASPEED_I2C_INTR_CTRL_REG)));

        /* Ack all interrupts */
        ack_all_intr = EXPECT_CALL(writel(u32_eq(test, 0xffffffff),
                                          u32_eq(test, ASPEED_I2C_INTR_STS_REG)));

        /* Disable everything */
        disable_aspeed = EXPECT_CALL(writel(u32_eq(test, 0),
                                            u32_eq(test, ASPEED_I2C_FUN_CTRL_REG)));

        /* Read Timing Register and initialize the aspeed clock */
        /* TODO(halehri): Maybe test this with better values */
        read_clk_reg_value = Returns(EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_AC_TIMING_REG1))),
                                     u32_return(test, 0));

        write_clk_reg_value = EXPECT_CALL(writel(u32_eq(test, 0),
                                                 u32_eq(test, ASPEED_I2C_AC_TIMING_REG1)));

        write_no_timeout_ctrl = EXPECT_CALL(writel(u32_eq(test, ASPEED_NO_TIMEOUT_CTRL),
                                                   u32_eq(test, ASPEED_I2C_AC_TIMING_REG2)));

        /* Enable Master mode */
        read_func_ctrl_reg = Returns(EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_FUN_CTRL_REG))),
                                     u32_return(test, 0));

        enable_master_mode = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_MASTER_EN | ASPEED_I2CD_MULTI_MASTER_DIS),
                                                u32_eq(test, ASPEED_I2C_FUN_CTRL_REG)));

        /* Enable interrupts again */
        enable_interrupts = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_INTR_ALL),
                                               u32_eq(test, ASPEED_I2C_INTR_CTRL_REG)));

        InSequence(test, read_cmd_reg_bus_busy, read_cmd_reg_sda_line_set,
                   write_stop_cmd, disable_intr, ack_all_intr, disable_aspeed,
                   read_clk_reg_value, write_clk_reg_value, write_no_timeout_ctrl,
                   read_func_ctrl_reg, enable_master_mode, enable_interrupts);

        aspeed_i2c_master_xfer_start_transaction(test, /*precondition=*/enable_interrupts);
}

static void aspeed_i2c_master_xfer_test_recover_bus_error(struct test *test) {
        /* Expectation set during the recovery phase. */
        struct mock_expectation *read_cmd_reg_bus_busy, *read_cmd_reg_sda_hung,
            *write_bus_recovery_cmd, *disable_intr, *ack_all_intr, *disable_aspeed,
            *read_clk_reg_value, *write_clk_reg_value, *write_no_timeout_ctrl,
            *read_func_ctrl_reg, *enable_master_mode, *enable_interrupts;

        /* Read command register and return state that indicates the bus to be busy */
        read_cmd_reg_bus_busy = Returns(EXPECT_CALL(readl(u32_eq(test,
                                                                 ASPEED_I2C_CMD_REG))),
                                        u32_return(test, ASPEED_I2CD_BUS_BUSY_STS));
        /* Read command register and return value that triggers a bus error (SDA hung) */
        read_cmd_reg_sda_hung = Returns(EXPECT_CALL(readl(u32_eq(test,
                                                                 ASPEED_I2C_CMD_REG))),
                                        u32_return(test, 0));
        /* This is the only difference between the previous test case and this one.
         * The Bus is not stopped and Bus Recovery Command gets written to
         * the command register.
         */
        write_bus_recovery_cmd = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_BUS_RECOVER_CMD),
                                                    u32_eq(test, ASPEED_I2C_CMD_REG)));

        /* Disable all interrupts */
        disable_intr = EXPECT_CALL(writel(u32_eq(test, 0),
                                          u32_eq(test, ASPEED_I2C_INTR_CTRL_REG)));

        /* Ack all interrupts */
        ack_all_intr = EXPECT_CALL(writel(u32_eq(test, 0xffffffff),
                                          u32_eq(test, ASPEED_I2C_INTR_STS_REG)));

        /* Disable everything */
        disable_aspeed = EXPECT_CALL(writel(u32_eq(test, 0),
                                            u32_eq(test, ASPEED_I2C_FUN_CTRL_REG)));

        /* Read Timing Register and initialize the aspeed clock */
        /* TODO(halehri): Maybe test this with better values */
        read_clk_reg_value = Returns(EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_AC_TIMING_REG1))),
                                     u32_return(test, 0));

        write_clk_reg_value = EXPECT_CALL(writel(u32_eq(test, 0),
                                                 u32_eq(test, ASPEED_I2C_AC_TIMING_REG1)));

        write_no_timeout_ctrl = EXPECT_CALL(writel(u32_eq(test, ASPEED_NO_TIMEOUT_CTRL),
                                                   u32_eq(test, ASPEED_I2C_AC_TIMING_REG2)));

        /* Enable Master mode */
        read_func_ctrl_reg = Returns(EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_FUN_CTRL_REG))),
                                     u32_return(test, 0));

        enable_master_mode = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_MASTER_EN | ASPEED_I2CD_MULTI_MASTER_DIS),
                                                u32_eq(test, ASPEED_I2C_FUN_CTRL_REG)));

        /* Enable interrupts again */
        enable_interrupts = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_INTR_ALL),
                                               u32_eq(test, ASPEED_I2C_INTR_CTRL_REG)));

        InSequence(test, read_cmd_reg_bus_busy, read_cmd_reg_sda_hung,
                   write_bus_recovery_cmd, disable_intr, ack_all_intr, disable_aspeed,
                   read_clk_reg_value, write_clk_reg_value, write_no_timeout_ctrl,
                   read_func_ctrl_reg, enable_master_mode, enable_interrupts);

        aspeed_i2c_master_xfer_start_transaction(test, /*precondition=*/enable_interrupts);
}

static u32 aspeed_i2c_get_base_clk(u32 reg_val)
{
	return reg_val & ASPEED_I2CD_TIME_BASE_DIVISOR_MASK;
}

static u32 aspeed_i2c_get_clk_high(u32 reg_val)
{
	return (reg_val & ASPEED_I2CD_TIME_SCL_HIGH_MASK) >>
			ASPEED_I2CD_TIME_SCL_HIGH_SHIFT;
}

static u32 aspeed_i2c_get_clk_low(u32 reg_val)
{
	return (reg_val & ASPEED_I2CD_TIME_SCL_LOW_MASK) >>
			ASPEED_I2CD_TIME_SCL_LOW_SHIFT;
}

static void aspeed_i2c_get_clk_reg_val_params_test(struct test *test,
						   u32 (*get_clk_reg_val)(u32),
						   u32 divisor,
						   u32 base_clk,
						   u32 clk_high,
						   u32 clk_low)
{
	u32 reg_val;

	reg_val = get_clk_reg_val(divisor);

	ASSERT_EQ(test,
		  reg_val & ~(ASPEED_I2CD_TIME_SCL_HIGH_MASK |
			      ASPEED_I2CD_TIME_SCL_LOW_MASK |
			      ASPEED_I2CD_TIME_BASE_DIVISOR_MASK),
		  0);

	EXPECT_EQ(test, aspeed_i2c_get_base_clk(reg_val), base_clk);
	EXPECT_EQ(test, aspeed_i2c_get_clk_high(reg_val), clk_high);
	EXPECT_EQ(test, aspeed_i2c_get_clk_low(reg_val), clk_low);
}

__visible_for_testing u32 aspeed_i2c_24xx_get_clk_reg_val(u32 divisor);

static void aspeed_i2c_24xx_get_clk_reg_val_params_test(struct test *test,
							u32 divisor,
							u32 base_clk,
							u32 clk_high,
							u32 clk_low)
{
	aspeed_i2c_get_clk_reg_val_params_test(test,
					       aspeed_i2c_24xx_get_clk_reg_val,
					       divisor,
					       base_clk,
					       clk_high,
					       clk_low);

}

/*
 * Verify that smallest possible divisors are handled correctly.
 */
static void aspeed_i2c_24xx_get_clk_reg_val_test_min(struct test *test)
{
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 0, 0, 0, 0);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 1, 0, 0, 0);
}

/*
 * Verify that largest possible divisors are handled correctly.
 */
static void aspeed_i2c_24xx_get_clk_reg_val_test_max(struct test *test)
{
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test,
						    ASPEED_I2C_24XX_MAX_DIVISOR,
						    ASPEED_I2CD_TIME_BASE_DIVISOR_MASK,
						    ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK,
						    ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test,
						    ASPEED_I2C_24XX_MAX_DIVISOR + 1,
						    ASPEED_I2CD_TIME_BASE_DIVISOR_MASK,
						    ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK,
						    ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test,
						    U32_MAX,
						    ASPEED_I2CD_TIME_BASE_DIVISOR_MASK,
						    ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK,
						    ASPEED_I2C_24XX_CLK_HIGH_LOW_MASK);
}

/*
 * Spot check values from the datasheet table.
 */
static void aspeed_i2c_24xx_get_clk_reg_val_test_datasheet(struct test *test)
{
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 6, 0, 2, 2);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 7, 0, 3, 2);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 16, 0, 7, 7);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 18, 1, 4, 3);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 491520, 15, 7, 6);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 524288, 15, 7, 7);
}

/*
 * Check that divisor that cannot be represented exactly is up down to the next
 * divisor that can be represented.
 */
static void aspeed_i2c_24xx_get_clk_reg_val_test_round_up(struct test *test)
{
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 16, 0, 7, 7);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 17, 1, 4, 3);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 18, 1, 4, 3);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 19, 1, 4, 4);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 491519, 15, 7, 6);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 491520, 15, 7, 6);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 524287, 15, 7, 7);
	aspeed_i2c_24xx_get_clk_reg_val_params_test(test, 524288, 15, 7, 7);
}

__visible_for_testing u32 aspeed_i2c_25xx_get_clk_reg_val(u32 divisor);

static void aspeed_i2c_25xx_get_clk_reg_val_params_test(struct test *test,
							u32 divisor,
							u32 base_clk,
							u32 clk_high,
							u32 clk_low)
{
	aspeed_i2c_get_clk_reg_val_params_test(test,
					       aspeed_i2c_25xx_get_clk_reg_val,
					       divisor,
					       base_clk,
					       clk_high,
					       clk_low);

}

/*
 * Verify that smallest possible divisors are handled correctly.
 */
static void aspeed_i2c_25xx_get_clk_reg_val_test_min(struct test *test)
{
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 0, 0, 0, 0);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 1, 0, 0, 0);
}

/*
 * Verify that largest possible divisors are handled correctly.
 */
static void aspeed_i2c_25xx_get_clk_reg_val_test_max(struct test *test)
{
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test,
						    ASPEED_I2C_25XX_MAX_DIVISOR,
						    ASPEED_I2CD_TIME_BASE_DIVISOR_MASK,
						    ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK,
						    ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test,
						    ASPEED_I2C_25XX_MAX_DIVISOR + 1,
						    ASPEED_I2CD_TIME_BASE_DIVISOR_MASK,
						    ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK,
						    ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test,
						    U32_MAX,
						    ASPEED_I2CD_TIME_BASE_DIVISOR_MASK,
						    ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK,
						    ASPEED_I2C_25XX_CLK_HIGH_LOW_MASK);
}

/*
 * Spot check values from the datasheet table.
 */
static void aspeed_i2c_25xx_get_clk_reg_val_test_datasheet(struct test *test)
{
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 6, 0, 2, 2);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 7, 0, 3, 2);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 32, 0, 15, 15);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 34, 1, 8, 7);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 2048, 6, 15, 15);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 2176, 7, 8, 7);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 3072, 7, 11, 11);
}

/*
 * Check that divisor that cannot be represented exactly is up down to the next
 * divisor that can be represented.
 */
static void aspeed_i2c_25xx_get_clk_reg_val_test_round_up(struct test *test)
{
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 2047, 6, 15, 15);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 2048, 6, 15, 15);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 2175, 7, 8, 7);
	aspeed_i2c_25xx_get_clk_reg_val_params_test(test, 2176, 7, 8, 7);
}

static int aspeed_i2c_test_init(struct test *test)
{
	struct mock_param_capturer *adap_capturer,
				   *irq_capturer,
				   *irq_ctx_capturer;
	struct aspeed_i2c_fake *i2c_fake;
	struct aspeed_i2c_test *ctx;

	i2c_fake = aspeed_i2c_fake_init(test, schedule_irq_handler_call_new);
	ctx = test_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	test->priv = ctx;

	ctx->i2c_fake = i2c_fake;

	// /* TODO(brendanhiggins@google.com): Fix this so mock_validate works. */
	// Between(1, 2, RetireOnSaturation(Returns(EXPECT_CALL(readl(any(test))),
        //                                          u32_return(test, 0))));
        // RetireOnSaturation(EXPECT_CALL(
        //     writel(u32_eq(test, 0),
        //            u32_eq(test, ASPEED_I2C_INTR_CTRL_REG))));
        // RetireOnSaturation(EXPECT_CALL(
        //     writel(any(test),
        //            u32_eq(test, ASPEED_I2C_INTR_STS_REG))));
	// RetireOnSaturation(EXPECT_CALL(
        //     writel(u32_eq(test, 0),
        //            u32_eq(test, ASPEED_I2C_FUN_CTRL_REG))));
	// RetireOnSaturation(EXPECT_CALL(
        //     writel(u32_ne(test, 0),
        //            u32_eq(test, ASPEED_I2C_FUN_CTRL_REG))));
	// RetireOnSaturation(EXPECT_CALL(
        //     writel(u32_eq(test, ASPEED_I2CD_INTR_ALL),
        //            u32_eq(test, ASPEED_I2C_INTR_CTRL_REG))));
	// RetireOnSaturation(EXPECT_CALL(
        //     writel(any(test),
        //            u32_eq(test, ASPEED_I2C_AC_TIMING_REG1))));
	// RetireOnSaturation(EXPECT_CALL(
        //     writel(u32_eq(test, ASPEED_NO_TIMEOUT_CTRL),
        //            u32_eq(test, ASPEED_I2C_AC_TIMING_REG2))));

	Returns(EXPECT_CALL(devm_ioremap_resource(any(test), any(test))),
                ptr_return(test, 0));

	Returns(EXPECT_CALL(__devm_reset_control_get(any(test),
						     any(test),
						     any(test),
						     any(test),
                                                     any(test))),
                int_return(test, 0));

	Returns(EXPECT_CALL(reset_control_deassert(any(test))),
                int_return(test, 0));

	irq_capturer = mock_ptr_capturer_create(test, any(test));
	irq_ctx_capturer = mock_ptr_capturer_create(test, any(test));
	Returns(EXPECT_CALL(devm_request_threaded_irq(any(test),
						      any(test),
						      capturer_to_matcher(irq_capturer),
						      any(test),
						      any(test),
						      any(test),
                                                      capturer_to_matcher(irq_ctx_capturer))),
                int_return(test, 0));

	adap_capturer = mock_ptr_capturer_create(test, any(test));
	ActionOnMatch(EXPECT_CALL(
            i2c_add_adapter(capturer_to_matcher(adap_capturer))),
                      INVOKE_REAL(test, i2c_add_adapter));

	ctx->pdev = of_fake_probe_platform_by_name(test,
						   "aspeed-i2c-bus",
						   "test-i2c-bus");
	ASSERT_NOT_ERR_OR_NULL(test, ctx->pdev);

	ASSERT_PARAM_CAPTURED(test, adap_capturer);
	ASSERT_PARAM_CAPTURED(test, irq_capturer);
	ASSERT_PARAM_CAPTURED(test, irq_ctx_capturer);
	ctx->adap = mock_capturer_get(adap_capturer, struct i2c_adapter *);
	ctx->irq_handler = mock_capturer_get(irq_capturer, irq_handler_t);
	ctx->irq_ctx = mock_capturer_get(irq_ctx_capturer, void *);

	/* Don't let mock expectations bleed into test cases. */
	mock_validate_expectations(mock_get_global_mock());

	INIT_WORK(&ctx->call_irq_handler, call_irq_handler);

	ctx->test = test;
	ctx->client = i2c_new_dummy(ctx->adap, 0x55);

	return 0;
}

static void aspeed_i2c_test_exit(struct test *test)
{
	struct aspeed_i2c_test *ctx = test->priv;

	platform_device_del(ctx->pdev);
}

static struct test_case aspeed_i2c_test_cases[] = {
	TEST_CASE(aspeed_i2c_master_xfer_test_basic),
	TEST_CASE(aspeed_i2c_master_xfer_test_idle_bus),
	// TEST_CASE(aspeed_i2c_master_xfer_test_recover_bus_reset),
	// TEST_CASE(aspeed_i2c_master_xfer_test_recover_bus_error),
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_min),
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_max),
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_datasheet),
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_round_up),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_min),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_max),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_datasheet),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_round_up),
	{},
};

static struct test_module aspeed_i2c_test_module = {
	.name = "aspeed-i2c-test",
	.init = aspeed_i2c_test_init,
	.exit = aspeed_i2c_test_exit,
	.test_cases = aspeed_i2c_test_cases,
};
module_test(aspeed_i2c_test_module);
