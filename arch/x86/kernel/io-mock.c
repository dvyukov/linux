#include <linux/mm.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <test/mock.h>

DEFINE_FUNCTION_MOCK(kunit_readb,
		     RETURNS(u8), PARAMS(const volatile void __iomem *));

DEFINE_FUNCTION_MOCK(kunit_readw,
		     RETURNS(u16), PARAMS(const volatile void __iomem *));

DEFINE_FUNCTION_MOCK(kunit_readl,
		     RETURNS(u32), PARAMS(const volatile void __iomem *));

#ifdef CONFIG_64BIT
DEFINE_FUNCTION_MOCK(kunit_readq,
		     RETURNS(u64), PARAMS(const volatile void __iomem *));
#endif /* CONFIG_64BIT */

DEFINE_FUNCTION_MOCK_VOID_RETURN(kunit_writeb,
				 PARAMS(u8, const volatile void __iomem *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(kunit_writew,
				 PARAMS(u16, const volatile void __iomem *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(kunit_writel,
				 PARAMS(u32, const volatile void __iomem *));

#ifdef CONFIG_64BIT
DEFINE_FUNCTION_MOCK_VOID_RETURN(kunit_writeq,
				 PARAMS(u64, const volatile void __iomem *));
#endif /* CONFIG_64BIT */
