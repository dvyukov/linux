#include <linux/init.h>
#include <linux/printk.h>
#include <linux/kthread.h>
#include <test/test.h>

extern char __test_modules_start;
extern char __test_modules_end;

static char __test_modules_copy[128*8];
static char* __test_modules_copy_end;

static int test_run_all_tests(void* arg)
{
	struct test_module **module;
	struct test_module ** const test_modules_start =
			(struct test_module **) &__test_modules_copy;
	struct test_module ** const test_modules_end =
			(struct test_module **) __test_modules_copy_end;
	bool has_test_failed = false;

	for (module = test_modules_start; module < test_modules_end; ++module) {
		if (test_run_tests(*module))
			has_test_failed = true;
	}

	return !has_test_failed;
}


int test_executor_init(void)
{
	int size = &__test_modules_end - &__test_modules_start;
	pr_err("kunit: size=%d %px/%px\n", size,  &__test_modules_end, &__test_modules_start);
	__memcpy(__test_modules_copy, &__test_modules_start, size);
	__test_modules_copy_end = __test_modules_copy + size;
	kthread_run(test_run_all_tests, NULL, "kunit");
	return 0;
}
