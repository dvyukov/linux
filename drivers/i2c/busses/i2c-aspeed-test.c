#include <test/test.h>
#include <test/mock.h>
#include <linux/platform_device_mock.h>
#include <linux/i2c.h>
#include <linux/i2c-mock.h>
#include <linux/interrupt.h>
#include <asm/io-mock.h>
#include "i2c-aspeed.h"

struct aspeed_i2c_test {
	struct test *test;
	struct platform_device *pdev;
	struct i2c_adapter *adap;
	irq_handler_t irq_handler;
	void *irq_ctx;
	struct work_struct call_irq_handler;
	struct i2c_client *client;
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

static void *schedule_irq_handler_call(struct test *test,
				       const void *params[],
				       int len)
{
	struct aspeed_i2c_test *ctx = test->priv;

	ASSERT_TRUE(ctx->test, schedule_work(&ctx->call_irq_handler));

	return ctx;
}

static void aspeed_i2c_master_xfer_test_basic(struct test *test)
{
	struct aspeed_i2c_test *ctx = test->priv;
	struct i2c_client *client = ctx->client;
	struct mock_expectation *handle;
	u8 msg[] = {0xae, 0x00};

	handle = EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_CMD_REG)));
	handle->action = u32_return(test, !ASPEED_I2CD_BUS_BUSY_STS);

	/* Start transaction. */
	EXPECT_CALL(writel(u32_eq(test, client->addr << 1),
			   u32_eq(test, ASPEED_I2C_BYTE_BUF_REG)));
	handle = EXPECT_CALL(writel(u32_eq(test,
					   ASPEED_I2CD_M_START_CMD |
					   ASPEED_I2CD_M_TX_CMD),
				    u32_eq(test, ASPEED_I2C_CMD_REG)));
	/*
	 * After the above expectation is hit the thread on which
	 * i2c_master_send is called will be put to sleep. However, we scheduled
	 * a worker to call the IRQ handler which should execute next.
	 */
	handle->action = invoke(test, schedule_irq_handler_call);

	/* Tell the handler a slave responded. */
	handle = EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	/* TODO(brendanhiggins): This is a pretty brittle way to make sure the
	 * other actions on this expectation are respected. A better way would
	 * be to use a sequence as described here:
	 * https://github.com/google/googletest/blob/master/googlemock/docs/CookBook.md#expecting-partially-ordered-calls
	 * However, this has not been implemented yet.
	 */
	handle->retire_on_saturation = true;
	handle->action = u32_return(test, ASPEED_I2CD_INTR_TX_ACK);
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_INTR_TX_ACK),
				    u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	handle->retire_on_saturation = true;
	/* Expect the first byte. */
	EXPECT_CALL(writel(u32_eq(test, msg[0]),
			   u32_eq(test, ASPEED_I2C_BYTE_BUF_REG)));
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_M_TX_CMD),
				    u32_eq(test, ASPEED_I2C_CMD_REG)));
	/* TODO(brendanhiggins): Brittle, should assert partial ordering. */
	handle->retire_on_saturation = true;
	/* Master should continue to wait to send another byte. */
	handle->action = invoke(test, schedule_irq_handler_call);

	/* Tell the handler the first byte was received. */
	handle = EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	/* TODO(brendanhiggins): Brittle, should assert partial ordering. */
	handle->retire_on_saturation = true;
	handle->action = u32_return(test, ASPEED_I2CD_INTR_TX_ACK);
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_INTR_TX_ACK),
				    u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	handle->retire_on_saturation = true;
	/* Expect the second byte. */
	EXPECT_CALL(writel(u32_eq(test, msg[1]),
			   u32_eq(test, ASPEED_I2C_BYTE_BUF_REG)));
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_M_TX_CMD),
				    u32_eq(test, ASPEED_I2C_CMD_REG)));
	/* TODO(brendanhiggins): Brittle, should assert partial ordering. */
	handle->retire_on_saturation = true;
	/* Master should continue to wait to receive ACK and STOP bus. */
	handle->action = invoke(test, schedule_irq_handler_call);

	/* Tell the handler the second byte was received. */
	handle = EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	/* TODO(brendanhiggins): Brittle, should assert partial ordering. */
	handle->retire_on_saturation = true;
	handle->action = u32_return(test, ASPEED_I2CD_INTR_TX_ACK);
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_INTR_TX_ACK),
				    u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	handle->retire_on_saturation = true;
	/* Expect a request to STOP the bus. */
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_M_STOP_CMD),
				    u32_eq(test, ASPEED_I2C_CMD_REG)));
	/* TODO(brendanhiggins): Brittle, should assert partial ordering. */
	handle->retire_on_saturation = true;
	/* Master should continue to wait to receive ACK and STOP bus. */
	handle->action = invoke(test, schedule_irq_handler_call);

	/* Tell the handler the bus has been stopped. */
	handle = EXPECT_CALL(readl(u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	/* TODO(brendanhiggins): Brittle, should assert partial ordering. */
	handle->retire_on_saturation = true;
	handle->action = u32_return(test, ASPEED_I2CD_INTR_NORMAL_STOP);
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_INTR_NORMAL_STOP),
				    u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	handle->retire_on_saturation = true;

	EXPECT_EQ(test,
		  ARRAY_SIZE(msg),
		  i2c_master_send(client, msg, ARRAY_SIZE(msg)));
}

static int aspeed_i2c_test_init(struct test *test)
{
	struct mock_param_capturer *adap_capturer,
				   *irq_capturer,
				   *irq_ctx_capturer;
	struct mock_expectation *handle;
	struct aspeed_i2c_test *ctx;

	mock_set_default_action(mock_get_global_mock(),
				"readl",
				readl,
				u32_return(test, 0));
	mock_set_default_action(mock_get_global_mock(),
				"writel",
				writel,
				int_return(test, 0));

	/* TODO(brendanhiggins@google.com): Fix this so mock_validate works. */
	handle = EXPECT_CALL(readl(any(test)));
	handle->action = u32_return(test, 0);
	handle->retire_on_saturation = true;
	handle->max_calls_expected = 2;
	handle = EXPECT_CALL(writel(u32_eq(test, 0),
				    u32_eq(test, ASPEED_I2C_INTR_CTRL_REG)));
	handle->retire_on_saturation = true;
	handle = EXPECT_CALL(writel(any(test),
				    u32_eq(test, ASPEED_I2C_INTR_STS_REG)));
	handle->retire_on_saturation = true;
	handle = EXPECT_CALL(writel(u32_eq(test, 0),
				    u32_eq(test, ASPEED_I2C_FUN_CTRL_REG)));
	handle->retire_on_saturation = true;
	handle = EXPECT_CALL(writel(u32_ne(test, 0),
				    u32_eq(test, ASPEED_I2C_FUN_CTRL_REG)));
	handle->retire_on_saturation = true;
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_I2CD_INTR_ALL),
				    u32_eq(test, ASPEED_I2C_INTR_CTRL_REG)));
	handle->retire_on_saturation = true;
	handle = EXPECT_CALL(writel(any(test),
				    u32_eq(test, ASPEED_I2C_AC_TIMING_REG1)));
	handle->retire_on_saturation = true;
	handle = EXPECT_CALL(writel(u32_eq(test, ASPEED_NO_TIMEOUT_CTRL),
				    u32_eq(test, ASPEED_I2C_AC_TIMING_REG2)));
	handle->retire_on_saturation = true;

	ctx = test_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	test->priv = ctx;

	handle = EXPECT_CALL(devm_ioremap_resource(any(test), any(test)));
	handle->action = int_return(test, 0);

	handle = EXPECT_CALL(__devm_reset_control_get(any(test),
						      any(test),
						      any(test),
						      any(test),
						      any(test)));
	handle->action = int_return(test, 0);
	handle = EXPECT_CALL(reset_control_deassert(any(test)));
	handle->action = int_return(test, 0);

	irq_capturer = mock_ptr_capturer_create(test, any(test));
	irq_ctx_capturer = mock_ptr_capturer_create(test, any(test));
	handle = EXPECT_CALL(devm_request_threaded_irq(any(test),
						       any(test),
						       capturer_to_matcher(irq_capturer),
						       any(test),
						       any(test),
						       any(test),
						       capturer_to_matcher(irq_ctx_capturer)));
	handle->action = int_return(test, 0);

	adap_capturer = mock_ptr_capturer_create(test, any(test));
	handle = EXPECT_CALL(
			i2c_add_adapter(capturer_to_matcher(adap_capturer)));
	handle->action = INVOKE_REAL(test, i2c_add_adapter);

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
	{},
};

static struct test_module aspeed_i2c_test_module = {
	.name = "aspeed-i2c-test",
	.init = aspeed_i2c_test_init,
	.exit = aspeed_i2c_test_exit,
	.test_cases = aspeed_i2c_test_cases,
};
module_test(aspeed_i2c_test_module);
