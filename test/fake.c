#include <test/fake.h>
#include <linux/io.h>

static struct fake_register_map_entry *fake_find_reg_action(
		struct fake_device *fd,
		phys_addr_t offset)
{
	struct fake_register_map_entry *reg_entry;
	struct test *test = fake_get_test(fd);

	for (reg_entry = fd->description->register_map;
	     reg_entry->valid_entry;
	     reg_entry++) {
		if (reg_entry->offset == offset)
			break;
	}

	ASSERT_NOT_ERR_OR_NULL(test, reg_entry);

	return reg_entry;
}

static u32 fake_readl(struct fake_device *fd, phys_addr_t offset)
{
	struct fake_register_map_entry *reg_entry;

	reg_entry = fake_find_reg_action(fd, offset);

	if (reg_entry->readl)
		return reg_entry->readl(fd);
	else
		return 0;
}

static void *fake_readl_action(struct mock_action *this,
			       const void **params,
			       int len)
{
	struct fake_device *fd = container_of(this,
					      struct fake_device,
					      readl_action);
	struct test *test = fake_get_test(fd);
	phys_addr_t offset;
	u32 *ret;

	ASSERT_EQ(test, len, 1);
	offset = CONVERT_TO_ACTUAL_TYPE(phys_addr_t, params[0]);
	ret = test_kzalloc(test, sizeof(*ret), GFP_KERNEL);
	*ret = fake_readl(fd, offset);

	return ret;
}

static void fake_writel(struct fake_device *fd, phys_addr_t offset, u32 value)
{
	struct fake_register_map_entry *reg_entry;

	reg_entry = fake_find_reg_action(fd, offset);

	if (reg_entry->writel)
		reg_entry->writel(fd, value);
}

static void *fake_writel_action(struct mock_action *this,
				const void **params,
				int len)
{
	struct fake_device *fd = container_of(this,
					      struct fake_device,
					      writel_action);
	struct test *test = fake_get_test(fd);
	phys_addr_t offset;
	u32 *ret, value;

	ASSERT_EQ(test, len, 2);
	value = CONVERT_TO_ACTUAL_TYPE(u32, params[0]);
	offset = CONVERT_TO_ACTUAL_TYPE(phys_addr_t, params[1]);
	ret = test_kzalloc(test, sizeof(*ret), GFP_KERNEL);
	*ret = 0;
	fake_writel(fd, offset, value);

	return ret;
}

void fake_device_init(struct test *test,
		      const struct fake_device_description *descr,
		      void *priv)
{
	struct fake_device *fd;

	fd = test_kzalloc(test, sizeof(*fd), GFP_KERNEL);

	fd->description = descr;
	fd->test = test;
	fd->priv = priv;
	fd->readl_action.do_action = fake_readl_action;
	fd->writel_action.do_action = fake_writel_action;

	mock_set_default_action(mock_get_global_mock(),
				"readl",
				readl,
				&fd->readl_action);
	mock_set_default_action(mock_get_global_mock(),
				"writel",
				writel,
				&fd->writel_action);
}
