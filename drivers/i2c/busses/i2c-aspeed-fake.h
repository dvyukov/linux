#ifndef _I2C_ASPEED_FAKE_H
#define _I2C_ASPEED_FAKE_H

#include <linux/i2c.h>
#include <test/fake.h>
#include "i2c-aspeed.h"

typedef void (*aspeed_i2c_fake_schedule_irq_t)(struct test *test);

struct aspeed_i2c_fake {
	struct i2c_msg *current_msg;
	aspeed_i2c_fake_schedule_irq_t schedule_irq;
	u32 interrupts_active;
	u32 interrupts_set;
	struct i2c_msg msgs[256];
	size_t msgs_count;
	bool address_active;
	bool can_restart;
	u8 tx_buffer;
	u8 rx_buffer;
};

static inline bool aspeed_i2c_fake_is_active(struct aspeed_i2c_fake *i2c_fake)
{
	return !!i2c_fake->current_msg;
}

struct aspeed_i2c_fake *aspeed_i2c_fake_init(struct test *test, aspeed_i2c_fake_schedule_irq_t schedule_irq);

#endif /* _I2C_ASPEED_FAKE_H */
