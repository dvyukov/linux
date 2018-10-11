#include <test/fake.h>
#include "i2c-aspeed-fake.h"

static void aspeed_i2c_fake_set_irq(struct fake_device *fd, u32 mask)
{
	struct aspeed_i2c_fake *i2c_fake = fake_get_data(fd);
	struct test *test = fake_get_test(fd);

	mask &= i2c_fake->interrupts_active;
	i2c_fake->interrupts_set |= mask;

	if (i2c_fake->interrupts_set)
		i2c_fake->schedule_irq(test);
}

static void aspeed_i2c_fake_write_intr_ctrl_reg(struct fake_device *fd, u32 value)
{
	struct aspeed_i2c_fake *i2c_fake = fake_get_data(fd);

	i2c_fake->interrupts_active = value;
}

static u32 aspeed_i2c_fake_read_intr_sts_reg(struct fake_device *fd)
{
	struct aspeed_i2c_fake *i2c_fake = fake_get_data(fd);


	return i2c_fake->interrupts_set;
}

static void aspeed_i2c_fake_write_intr_sts_reg(struct fake_device *fd, u32 value)
{
	struct aspeed_i2c_fake *i2c_fake = fake_get_data(fd);

	i2c_fake->interrupts_set &= ~value;
}

static u32 aspeed_i2c_fake_read_byte_buf_reg(struct fake_device *fd)
{
	struct aspeed_i2c_fake *i2c_fake = fake_get_data(fd);

	return ((u32)i2c_fake->rx_buffer) << 8;
}

static void aspeed_i2c_fake_write_byte_buf_reg(struct fake_device *fd, u32 value)
{
	struct aspeed_i2c_fake *i2c_fake = fake_get_data(fd);

	i2c_fake->tx_buffer = value & 0xff;
}

static void aspeed_i2c_fake_write_command_reg(struct fake_device *fd, u32 value)
{
	struct aspeed_i2c_fake *i2c_fake = fake_get_data(fd);
	struct test *test = fake_get_test(fd);

	if (value & ASPEED_I2CD_M_START_CMD) {
		EXPECT_TRUE(test, i2c_fake->can_restart);
		i2c_fake->current_msg = &i2c_fake->msgs[i2c_fake->msgs_count++];
		i2c_fake->current_msg->buf = test_kzalloc(test, 256, GFP_KERNEL);
		i2c_fake->address_active = true;
		i2c_fake->can_restart = true;
	}

	if (value & ASPEED_I2CD_M_TX_CMD) {
		ASSERT_TRUE(test, aspeed_i2c_fake_is_active(i2c_fake));
		if (i2c_fake->address_active) {
			i2c_fake->current_msg->addr = i2c_fake->tx_buffer >> 1;
			i2c_fake->address_active = false;
		} else {
			i2c_fake->current_msg->buf[i2c_fake->current_msg->len++] = i2c_fake->tx_buffer;
		}
		aspeed_i2c_fake_set_irq(fd, ASPEED_I2CD_INTR_TX_ACK);
	}

	if (value & ASPEED_I2CD_M_RX_CMD) {
		ASSERT_TRUE(test, aspeed_i2c_fake_is_active(i2c_fake));
		i2c_fake->rx_buffer = i2c_fake->current_msg->buf[i2c_fake->current_msg->len++];
		i2c_fake->can_restart = false;
		aspeed_i2c_fake_set_irq(fd, ASPEED_I2CD_INTR_RX_DONE);
	}

	if (value & ASPEED_I2CD_M_S_RX_CMD_LAST) {
		i2c_fake->can_restart = true;
	}

	if (value & ASPEED_I2CD_M_STOP_CMD) {
		EXPECT_TRUE(test, i2c_fake->can_restart);
		i2c_fake->current_msg = NULL;
		aspeed_i2c_fake_set_irq(fd, ASPEED_I2CD_INTR_NORMAL_STOP);
	}
}

static struct fake_register_map_entry aspeed_i2c_fake_register_map[] = {
	FAKE_32_NOP(ASPEED_I2C_FUN_CTRL_REG),
	FAKE_32_NOP(ASPEED_I2C_AC_TIMING_REG1),
	FAKE_32_NOP(ASPEED_I2C_AC_TIMING_REG2),
	FAKE_32_WO(ASPEED_I2C_INTR_CTRL_REG, aspeed_i2c_fake_write_intr_ctrl_reg),
	FAKE_32_RW(ASPEED_I2C_INTR_STS_REG, aspeed_i2c_fake_read_intr_sts_reg, aspeed_i2c_fake_write_intr_sts_reg),
	FAKE_32_WO(ASPEED_I2C_CMD_REG, aspeed_i2c_fake_write_command_reg),
	FAKE_32_NOP(ASPEED_I2C_DEV_ADDR_REG),
	FAKE_32_RW(ASPEED_I2C_BYTE_BUF_REG, aspeed_i2c_fake_read_byte_buf_reg, aspeed_i2c_fake_write_byte_buf_reg),
	{},
};

static struct fake_device_description aspeed_i2c_fake_device = {
	.register_map = aspeed_i2c_fake_register_map,
};


struct aspeed_i2c_fake *aspeed_i2c_fake_init(struct test *test, aspeed_i2c_fake_schedule_irq_t schedule_irq)
{
	struct aspeed_i2c_fake *i2c_fake;

	i2c_fake = test_kzalloc(test, sizeof(*i2c_fake), GFP_KERNEL);

	i2c_fake->can_restart = true;
	i2c_fake->schedule_irq = schedule_irq;

	fake_device_init(test, &aspeed_i2c_fake_device, i2c_fake);

	return i2c_fake;
}

