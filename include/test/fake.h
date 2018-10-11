#ifndef _TEST_FAKE_H
#define _TEST_FAKE_H

#include <test/mock.h>

struct fake_device;

struct fake_register_map_entry {
	phys_addr_t offset;
	bool valid_entry;
	u8 (*readb)(struct fake_device *fd);
	u16 (*readw)(struct fake_device *fd);
	u32 (*readl)(struct fake_device *fd);
	u64 (*readq)(struct fake_device *fd);
	void (*writeb)(struct fake_device *fd, u8 value);
	void (*writew)(struct fake_device *fd, u16 value);
	void (*writel)(struct fake_device *fd, u32 value);
	void (*writeq)(struct fake_device *fd, u64 value);
};

#define FAKE_32_RW(offset_, read, write) {				       \
	.offset = offset_,						       \
	.valid_entry = true,						       \
	.readl = read,							       \
	.writel = write,						       \
}

#define FAKE_32_RO(offset, read) FAKE_32_RW(offset, read, NULL)
#define FAKE_32_WO(offset, write) FAKE_32_RW(offset, NULL, write)
#define FAKE_32_NOP(offset) FAKE_32_RW(offset, NULL, NULL)

struct fake_device_description {
	struct fake_register_map_entry *register_map;
};

struct fake_device {
	/* private */
	struct mock_action readl_action;
	struct mock_action writel_action;
	const struct fake_device_description *description;
	struct test *test;
	void *priv;
};

static inline struct test *fake_get_test(struct fake_device *fd)
{
	return fd->test;
}

static inline void *fake_get_data(struct fake_device *fd)
{
	return fd->priv;
}

void fake_device_init(struct test *test,
		      const struct fake_device_description *descr,
		      void *priv);

#endif /* _TEST_FAKE_H */
