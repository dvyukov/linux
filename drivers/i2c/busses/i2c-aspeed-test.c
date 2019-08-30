#include <test/test.h>
#include <test/mock.h>
#include <linux/delay.h>
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
DEFINE_FUNCTION_MOCK(kunit_devm_request_irq,
		     RETURNS(int),
		     PARAMS(struct device *,
			    unsigned int,
			    irq_handler_t,
			    //irq_handler_t,
			    unsigned long,
			    const char *,
			    void *));
DEFINE_FUNCTION_MOCK(devm_clk_get,
		     RETURNS(struct clk *),
		     PARAMS(struct device *, const char *));
DEFINE_FUNCTION_MOCK_VOID_RETURN(devm_clk_put,
				 PARAMS(struct device *, struct clk *));

static void call_irq_handler(struct work_struct *work)
{
	struct aspeed_i2c_test *ctx = container_of(work,
						   struct aspeed_i2c_test,
						   call_irq_handler);

	EXPECT_EQ(ctx->test, IRQ_HANDLED, ctx->irq_handler(0, ctx->irq_ctx));
}

static void schedule_irq_handler_call(struct test *test)
{
	struct aspeed_i2c_test *ctx = test->priv;

	/*ASSERT_TRUE(ctx->test,*/ schedule_work(&ctx->call_irq_handler)/*)*/;
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
        struct aspeed_i2c_test *ctx = test->priv;
	struct aspeed_i2c_fake *i2c_fake = ctx->i2c_fake;
        struct i2c_client *client = ctx->client;
        u8 msg[] = {0xae, 0x00};
	int i;

	i2c_fake->busy = true;

        ASSERT_EQ(test,
                  ARRAY_SIZE(msg),
                  i2c_master_send(client, msg, ARRAY_SIZE(msg)));

	EXPECT_FALSE(test, i2c_fake->busy);

	ASSERT_EQ(test, i2c_fake->msgs_count, 1);
	EXPECT_EQ(test, client->addr, i2c_fake->msgs->addr);
	EXPECT_EQ(test, i2c_fake->msgs->len, ARRAY_SIZE(msg));
	for (i = 0; i < ARRAY_SIZE(msg); i++)
		EXPECT_EQ(test, i2c_fake->msgs->buf[i], msg[i]);
}

static void aspeed_i2c_master_xfer_test_recover_bus_reset(struct test *test)
{
        struct aspeed_i2c_test *ctx = test->priv;
	struct aspeed_i2c_fake *i2c_fake = ctx->i2c_fake;
        struct i2c_client *client = ctx->client;
        u8 msg[] = {0xae, 0x00};
	int i;

	i2c_fake->scl_hung = true;

        ASSERT_EQ(test,
                  ARRAY_SIZE(msg),
                  i2c_master_send(client, msg, ARRAY_SIZE(msg)));

	EXPECT_FALSE(test, i2c_fake->scl_hung);

	ASSERT_EQ(test, i2c_fake->msgs_count, 1);
	EXPECT_EQ(test, client->addr, i2c_fake->msgs->addr);
	EXPECT_EQ(test, i2c_fake->msgs->len, ARRAY_SIZE(msg));
	for (i = 0; i < ARRAY_SIZE(msg); i++)
		EXPECT_EQ(test, i2c_fake->msgs->buf[i], msg[i]);
}

static void aspeed_i2c_master_xfer_test_recover_bus_error(struct test *test) {
        struct aspeed_i2c_test *ctx = test->priv;
	struct aspeed_i2c_fake *i2c_fake = ctx->i2c_fake;
        struct i2c_client *client = ctx->client;
        u8 msg[] = {0xae, 0x00};
	int i;

	i2c_fake->sda_hung = true;

        ASSERT_EQ(test,
                  ARRAY_SIZE(msg),
                  i2c_master_send(client, msg, ARRAY_SIZE(msg)));

	EXPECT_FALSE(test, i2c_fake->sda_hung);

	ASSERT_EQ(test, i2c_fake->msgs_count, 1);
	EXPECT_EQ(test, client->addr, i2c_fake->msgs->addr);
	EXPECT_EQ(test, i2c_fake->msgs->len, ARRAY_SIZE(msg));
	for (i = 0; i < ARRAY_SIZE(msg); i++)
		EXPECT_EQ(test, i2c_fake->msgs->buf[i], msg[i]);

	msleep_interruptible(1000000000);	
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

struct clk {
	struct clk_core	*core;
	struct device *dev;
	const char *dev_id;
	const char *con_id;
	unsigned long min_rate;
	unsigned long max_rate;
	unsigned int exclusive_count;
	struct hlist_node clks_node;
};

static int aspeed_i2c_test_init(struct test *test)
{
	struct mock_param_capturer *adap_capturer,
				   *irq_capturer,
				   *irq_ctx_capturer;
	struct aspeed_i2c_fake *i2c_fake;
	struct aspeed_i2c_test *ctx;
	struct clk *clk;

	clk = test_kzalloc(test, sizeof(*clk), GFP_KERNEL);
	i2c_fake = aspeed_i2c_fake_init(test, schedule_irq_handler_call);
	ctx = test_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	test->priv = ctx;

	ctx->i2c_fake = i2c_fake;

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
	Returns(EXPECT_CALL(kunit_devm_request_irq(any(test),
						      any(test),
						      capturer_to_matcher(irq_capturer),
						      any(test),
						      //any(test),
						      any(test),
                                                      capturer_to_matcher(irq_ctx_capturer))),
                int_return(test, 0));
	Returns(EXPECT_CALL(devm_clk_get(any(test), any(test))), ptr_return(test, clk));
	Returns(EXPECT_CALL(devm_clk_put(any(test), any(test))), int_return(test, 0));

	adap_capturer = mock_ptr_capturer_create(test, any(test));
	ActionOnMatch(EXPECT_CALL(
            i2c_add_adapter(capturer_to_matcher(adap_capturer))),
                      INVOKE_REAL(test, i2c_add_adapter));

	ctx->pdev = of_fake_probe_platform_by_name(test,
						   "aspeed-i2c-bus",
						   "test-i2c-bus");
	/* Don't let mock expectations bleed into test cases. */
	mock_validate_expectations(mock_get_global_mock());
	ASSERT_NOT_ERR_OR_NULL(test, ctx->pdev);

	ASSERT_PARAM_CAPTURED(test, adap_capturer);
	ASSERT_PARAM_CAPTURED(test, irq_capturer);
	ASSERT_PARAM_CAPTURED(test, irq_ctx_capturer);
	ctx->adap = mock_capturer_get(adap_capturer, struct i2c_adapter *);
	ctx->irq_handler = mock_capturer_get(irq_capturer, irq_handler_t);
	ctx->irq_ctx = mock_capturer_get(irq_ctx_capturer, void *);

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
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_min),
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_max),
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_datasheet),
	TEST_CASE(aspeed_i2c_24xx_get_clk_reg_val_test_round_up),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_min),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_max),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_datasheet),
	TEST_CASE(aspeed_i2c_25xx_get_clk_reg_val_test_round_up),
	TEST_CASE(aspeed_i2c_master_xfer_test_basic),
	TEST_CASE(aspeed_i2c_master_xfer_test_idle_bus),
	TEST_CASE(aspeed_i2c_master_xfer_test_recover_bus_reset),
	TEST_CASE(aspeed_i2c_master_xfer_test_recover_bus_error),
	{},
};

static struct test_module aspeed_i2c_test_module = {
	.name = "aspeed-i2c-test",
	.init = aspeed_i2c_test_init,
	.exit = aspeed_i2c_test_exit,
	.test_cases = aspeed_i2c_test_cases,
};
module_test(aspeed_i2c_test_module);
