#include <test/mock.h>
#include <linux/i2c.h>
#include <linux/i2c-mock.h>

DEFINE_FUNCTION_MOCK(i2c_add_adapter,
		     RETURNS(int),
		     PARAMS(struct i2c_adapter *));

DEFINE_STRUCT_CLASS_MOCK(METHOD(master_xfer), CLASS(i2c_adapter),
			 RETURNS(int),
			 PARAMS(struct i2c_adapter *, struct i2c_msg *, int));

DEFINE_STRUCT_CLASS_MOCK(METHOD(smbus_xfer), CLASS(i2c_adapter),
			 RETURNS(int),
			 PARAMS(struct i2c_adapter *,
				u16,
				unsigned short,
				char,
				u8,
				int,
				union i2c_smbus_data *));

DEFINE_STRUCT_CLASS_MOCK(METHOD(functionality), CLASS(i2c_adapter),
			 RETURNS(u32),
			 PARAMS(struct i2c_adapter *));

static const struct i2c_algorithm i2c_mock_algorithm = {
	.master_xfer = master_xfer,
	.smbus_xfer = smbus_xfer,
	.functionality = functionality,
};

static int i2c_mock_num_vf(struct device *dev)
{
	return 1;
}

static struct bus_type i2c_mock_bus = {
	.name = "i2c_mock_bus",
	.num_vf = i2c_mock_num_vf,
};

static void i2c_mock_release(struct device *dev)
{
}

struct device i2c_mock_device  = {
	.init_name = "i2c_mock_device",
	.bus = &i2c_mock_bus,
	.release = i2c_mock_release,
};

static int i2c_mock_init(struct MOCK(i2c_adapter) *mock_adap)
{
	struct i2c_adapter *adap = mock_get_trgt(mock_adap);
	struct test *test = mock_get_test(mock_adap);
	int ret;

	ret = bus_register(&i2c_mock_bus);
	if (ret < 0)
		return ret;

	ret = device_register(&i2c_mock_device);
	if (ret < 0)
		return ret;

	adap->algo = &i2c_mock_algorithm;
	adap->dev.parent = &i2c_mock_device;
	snprintf(adap->name, sizeof(adap->name), "i2c_mock");

	ret = mock_set_default_action(mock_get_ctrl(mock_adap),
				      "functionality",
				      functionality,
				      int_return(test,
						 I2C_FUNC_I2C |
						 I2C_FUNC_SMBUS_EMUL |
						 I2C_FUNC_SMBUS_READ_BLOCK_DATA));

	if (ret < 0)
		return ret;

	/*
	 * TODO(brendanhiggins): we should not need this in the future since
	 * i2c_add_adapter is redirect-mockable, so this action should be set
	 * automatically.
	 */
	ret = mock_set_default_action(mock_get_global_mock(),
				      "i2c_add_adapter",
				      i2c_add_adapter,
				      INVOKE_REAL(test, i2c_add_adapter));

	ret = i2c_add_adapter(adap);
	if (ret < 0)
		return ret;

	return 0;
}

DEFINE_STRUCT_CLASS_MOCK_INIT(i2c_adapter, i2c_mock_init);
