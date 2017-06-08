#include <test/mock.h>
#include <linux/i2c.h>

DECLARE_STRUCT_CLASS_MOCK_PREREQS(i2c_adapter);

DECLARE_STRUCT_CLASS_MOCK(METHOD(master_xfer), CLASS(i2c_adapter),
			  RETURNS(int),
			  PARAMS(struct i2c_adapter *, struct i2c_msg *, int));

DECLARE_STRUCT_CLASS_MOCK(METHOD(smbus_xfer), CLASS(i2c_adapter),
			  RETURNS(int),
			  PARAMS(struct i2c_adapter *,
				 u16,
				 unsigned short,
				 char,
				 u8,
				 int,
				 union i2c_smbus_data *));

DECLARE_STRUCT_CLASS_MOCK(METHOD(functionality), CLASS(i2c_adapter),
			  RETURNS(u32),
			  PARAMS(struct i2c_adapter *));

DECLARE_STRUCT_CLASS_MOCK_INIT(i2c_adapter);

static inline struct mock_expectation *mock_master_i2c_smbus_read_byte_data(
		struct i2c_client *client, struct mock_param_matcher *u8_matcher)
{
	struct mock *mock = from_i2c_adapter_to_mock(client->adapter);
	struct test *test = mock->test;

	return EXPECT_CALL(smbus_xfer(mock, u16_eq(test, client->addr),
				      ushort_eq(test, client->flags),
				      char_eq(test, I2C_SMBUS_READ),
				      u8_matcher,
				      int_eq(test, I2C_SMBUS_BYTE_DATA),
				      any(test)));
}

DECLARE_REDIRECT_MOCKABLE(i2c_add_adapter, RETURNS(int), PARAMS(struct i2c_adapter *));
DECLARE_FUNCTION_MOCK(i2c_add_adapter, RETURNS(int), PARAMS(struct i2c_adapter *));

static inline struct i2c_driver *i2c_driver_find(const char *name)
{
	struct device_driver *driver;

	driver = driver_find(name, &i2c_bus_type);
	if (!driver)
		return NULL;

	return to_i2c_driver(driver);
}
