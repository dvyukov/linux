#ifndef _I2C_ASPEED_H
#define _I2C_ASPEED_H

#include <linux/bitops.h>

/* I2C Register */
#define ASPEED_I2C_FUN_CTRL_REG				0x00
#define ASPEED_I2C_AC_TIMING_REG1			0x04
#define ASPEED_I2C_AC_TIMING_REG2			0x08
#define ASPEED_I2C_INTR_CTRL_REG			0x0c
#define ASPEED_I2C_INTR_STS_REG				0x10
#define ASPEED_I2C_CMD_REG				0x14
#define ASPEED_I2C_DEV_ADDR_REG				0x18
#define ASPEED_I2C_BYTE_BUF_REG				0x20

/* Global Register Definition */
/* 0x00 : I2C Interrupt Status Register  */
/* 0x08 : I2C Interrupt Target Assignment  */

/* Device Register Definition */
/* 0x00 : I2CD Function Control Register  */
#define ASPEED_I2CD_MULTI_MASTER_DIS			BIT(15)
#define ASPEED_I2CD_SDA_DRIVE_1T_EN			BIT(8)
#define ASPEED_I2CD_M_SDA_DRIVE_1T_EN			BIT(7)
#define ASPEED_I2CD_M_HIGH_SPEED_EN			BIT(6)
#define ASPEED_I2CD_SLAVE_EN				BIT(1)
#define ASPEED_I2CD_MASTER_EN				BIT(0)

/* 0x04 : I2CD Clock and AC Timing Control Register #1 */
#define ASPEED_I2CD_TIME_TBUF_MASK			GENMASK(31, 28)
#define ASPEED_I2CD_TIME_THDSTA_MASK			GENMASK(27, 24)
#define ASPEED_I2CD_TIME_TACST_MASK			GENMASK(23, 20)
#define ASPEED_I2CD_TIME_SCL_HIGH_SHIFT			16
#define ASPEED_I2CD_TIME_SCL_HIGH_MASK			GENMASK(19, 16)
#define ASPEED_I2CD_TIME_SCL_LOW_SHIFT			12
#define ASPEED_I2CD_TIME_SCL_LOW_MASK			GENMASK(15, 12)
#define ASPEED_I2CD_TIME_BASE_DIVISOR_MASK		GENMASK(3, 0)
#define ASPEED_I2CD_TIME_SCL_REG_MAX			GENMASK(3, 0)
/* 0x08 : I2CD Clock and AC Timing Control Register #2 */
#define ASPEED_NO_TIMEOUT_CTRL				0

/* 0x0c : I2CD Interrupt Control Register &
 * 0x10 : I2CD Interrupt Status Register
 *
 * These share bit definitions, so use the same values for the enable &
 * status bits.
 */
#define ASPEED_I2CD_INTR_SDA_DL_TIMEOUT			BIT(14)
#define ASPEED_I2CD_INTR_BUS_RECOVER_DONE		BIT(13)
#define ASPEED_I2CD_INTR_SLAVE_MATCH			BIT(7)
#define ASPEED_I2CD_INTR_SCL_TIMEOUT			BIT(6)
#define ASPEED_I2CD_INTR_ABNORMAL			BIT(5)
#define ASPEED_I2CD_INTR_NORMAL_STOP			BIT(4)
#define ASPEED_I2CD_INTR_ARBIT_LOSS			BIT(3)
#define ASPEED_I2CD_INTR_RX_DONE			BIT(2)
#define ASPEED_I2CD_INTR_TX_NAK				BIT(1)
#define ASPEED_I2CD_INTR_TX_ACK				BIT(0)
#define ASPEED_I2CD_INTR_ALL						       \
		(ASPEED_I2CD_INTR_SDA_DL_TIMEOUT |			       \
		 ASPEED_I2CD_INTR_BUS_RECOVER_DONE |			       \
		 ASPEED_I2CD_INTR_SCL_TIMEOUT |				       \
		 ASPEED_I2CD_INTR_ABNORMAL |				       \
		 ASPEED_I2CD_INTR_NORMAL_STOP |				       \
		 ASPEED_I2CD_INTR_ARBIT_LOSS |				       \
		 ASPEED_I2CD_INTR_RX_DONE |				       \
		 ASPEED_I2CD_INTR_TX_NAK |				       \
		 ASPEED_I2CD_INTR_TX_ACK)

/* 0x14 : I2CD Command/Status Register   */
#define ASPEED_I2CD_SCL_LINE_STS			BIT(18)
#define ASPEED_I2CD_SDA_LINE_STS			BIT(17)
#define ASPEED_I2CD_BUS_BUSY_STS			BIT(16)
#define ASPEED_I2CD_BUS_RECOVER_CMD			BIT(11)

/* Command Bit */
#define ASPEED_I2CD_M_STOP_CMD				BIT(5)
#define ASPEED_I2CD_M_S_RX_CMD_LAST			BIT(4)
#define ASPEED_I2CD_M_RX_CMD				BIT(3)
#define ASPEED_I2CD_S_TX_CMD				BIT(2)
#define ASPEED_I2CD_M_TX_CMD				BIT(1)
#define ASPEED_I2CD_M_START_CMD				BIT(0)

/* 0x18 : I2CD Slave Device Address Register   */
#define ASPEED_I2CD_DEV_ADDR_MASK			GENMASK(6, 0)

#endif /* _I2C_ASPEED_H */
