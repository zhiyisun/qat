/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2018 - 2021 Intel Corporation */
#ifndef ADF_4XXX_HW_DATA_H_
#define ADF_4XXX_HW_DATA_H_

#include <adf_accel_devices.h>

#define DEFAULT_4XXX_ASYM_AE_MASK 0x03
#define DEFAULT_401XX_ASYM_AE_MASK 0x3F

/* PCIe configuration space */
#define ADF_4XXX_RX_RINGS_OFFSET 1
#define ADF_4XXX_TX_RINGS_MASK 0x1

#define ADF_4XXX_MAX_ACCELERATORS 1
#define ADF_4XXX_MAX_ACCELENGINES 9

/* 2 Accel units dedicated to services and */
/* 1 Accel unit dedicated to Admin AE */
#define ADF_4XXX_MAX_ACCELUNITS   3

/* Physical function fuses */
#define ADF_4XXX_FUSECTL0_OFFSET (0x2C8)
#define ADF_4XXX_FUSECTL1_OFFSET (0x2CC)
#define ADF_4XXX_FUSECTL2_OFFSET (0x2D0)
#define ADF_4XXX_FUSECTL3_OFFSET (0x2D4)
#define ADF_4XXX_FUSECTL4_OFFSET (0x2D8)
#define ADF_4XXX_FUSECTL5_OFFSET (0x2DC)

#define ADF_4XXX_ACCELERATORS_MASK (0x1)
#define ADF_4XXX_ACCELENGINES_MASK (0x1FF)
#define ADF_4XXX_ADMIN_AE_MASK (0x100)

#define ADF_4XXX_HICPPAGENTCMDPARERRLOG_MASK (0x1F)

#define ADF_4XXX_ETR_MAX_BANKS 64
/*MSIX interrupt*/
#define ADF_4XXX_SMIAPF_RP_X0_MASK_OFFSET (0x41A040)
#define ADF_4XXX_SMIAPF_RP_X1_MASK_OFFSET (0x41A044)
#define ADF_4XXX_SMIAPF_MASK_OFFSET (0x41A084)

/* Bank and ring configuration */
#define ADF_4XXX_NUM_RINGS_PER_BANK 2
#define ADF_4XXX_NUM_SERVICES_PER_BANK 1
#define ADF_4XXX_NUM_BANKS_PER_VF 4
/* Error detection and correction */
#define ADF_4XXX_AE_CTX_ENABLES(i) (0x600818 + ((i) * 0x1000))
#define ADF_4XXX_AE_MISC_CONTROL(i) (0x600960 + ((i) * 0x1000))
#define ADF_4XXX_ENABLE_AE_ECC_ERR BIT(28)
#define ADF_4XXX_ENABLE_AE_ECC_PARITY_CORR (BIT(24) | BIT(12))
#define ADF_4XXX_UERRSSMSH(i) (0x18 + ((i) * 0x800))
#define ADF_4XXX_CERRSSMSH(i) (0x10 + ((i) * 0x800))
#define ADF_4XXX_ERRSSMSH_CERR BIT(0)
#define ADF_4XXX_ERRSSMSH_EN BIT(3)
#define ADF_4XXX_PF2VM_OFFSET(i)	(0x40B010 + ((i) * 0x20))
#define ADF_4XXX_VM2PF_OFFSET(i)	(0x40B014 + ((i) * 0x20))
#define ADF_4XXX_VINTMSK_OFFSET(i)	(0x40B004 + ((i) * 0x20))

/* Slice power down register */
#define ADF_4XXX_SLICEPWRDOWN(i) (0x2C((i) * 0x800))

/* Return interrupt accelerator source mask */
#define ADF_4XXX_IRQ_SRC_MASK(accel) (1 << (accel))

/* VF2PF interrupt source register */
#define ADF_4XXX_VM2PF_SOU (0x41A180)
/* VF2PF interrupt mask register */
#define ADF_4XXX_VM2PF_MSK (0x41A1C0)

#define ADF_4XXX_FCU_STATUS (0x641004)

#define ADF_4XXX_SHINTMASKSSM_ATH_CPH (0xF0)
#define ADF_4XXX_SHINTMASKSSM_CPR_XLT (0xF4)
#define ADF_4XXX_SHINTMASKSSM_DCPR_UCS (0xFC)
#define ADF_4XXX_SHINTMASKSSM_PKE (0x100)

#define ADF_4XXX_SHINTMASKSSM_ATH_CPH_OFFSET(accel) \
	(ADF_4XXX_SHINTMASKSSM_ATH_CPH + ((accel) * 0x4000))
#define ADF_4XXX_SHINTMASKSSM_CPR_XLT_OFFSET(accel) \
	(ADF_4XXX_SHINTMASKSSM_CPR_XLT + ((accel) * 0x4000))
#define ADF_4XXX_SHINTMASKSSM_DCPR_UCS_OFFSET(accel) \
	(ADF_4XXX_SHINTMASKSSM_DCPR_UCS + ((accel) * 0x4000))
#define ADF_4XXX_SHINTMASKSSM_PKE_OFFSET(accel) \
	(ADF_4XXX_SHINTMASKSSM_PKE + ((accel) * 0x4000))

#define ADF_4XXX_SHINTMASKSSM_ATH_CPH_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(3) | \
	 BIT(17) | BIT(18) | BIT(19))

#define ADF_4XXX_SHINTMASKSSM_CPR_XLT_MASK (BIT(0) | BIT(16))
#define ADF_4XXX_SHINTMASKSSM_DCPR_UCS_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(16) | BIT(17))

#define ADF_4XXX_SHINTMASKSSM_PKE_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(4) | BIT(5))

#define ADF_4XXX_SLICEHANGSTATUS_ATH_CPH (0x84)
#define ADF_4XXX_SLICEHANGSTATUS_CPR_XLT (0x88)
#define ADF_4XXX_SLICEHANGSTATUS_WAT_WCP (0x8C)
#define ADF_4XXX_SLICEHANGSTATUS_DCPR_UCS (0x90)
#define ADF_4XXX_SLICEHANGSTATUS_PKE (0x94)

#define ADF_4XXX_SLPAGEFWDERR (0x19C)

#define ADF_4XXX_SSMSOFTERRORPARITY_SRC (0x9C)
#define ADF_4XXX_SSMSOFTERRORPARITY_ATH_CPH (0xA0)
#define ADF_4XXX_SSMSOFTERRORPARITY_CPR_XLT (0xA4)
#define ADF_4XXX_SSMSOFTERRORPARITY_WAT_WCP (0xA8)
#define ADF_4XXX_SSMSOFTERRORPARITY_DCPR_UCS (0xAC)
#define ADF_4XXX_SSMSOFTERRORPARITY_PKE (0xB0)

#define ADF_4XXX_SSMSOFTERRORPARITYMASK_SRC (0xB8)
#define ADF_4XXX_SSMSOFTERRORPARITYMASK_ATH_CPH (0xBC)
#define ADF_4XXX_SSMSOFTERRORPARITYMASK_CPR_XLT (0xC0)
#define ADF_4XXX_SSMSOFTERRORPARITYMASK_DCPR_UCS (0xC8)
#define ADF_4XXX_SSMSOFTERRORPARITYMASK_PKE (0xCC)

/* Accelerator spp parity error mask registers */
#define ADF_4XXX_SPPPARERRMSK_ATH_CPH  (0x204)
#define ADF_4XXX_SPPPARERRMSK_CPR_XLT  (0x208)
#define ADF_4XXX_SPPPARERRMSK_DCPR_UCS (0x210)
#define ADF_4XXX_SPPPARERRMSK_PKE      (0x214)

/* Accelerator spp parity error mask
 * BIT(0-3)   ath0-ath3
 * BIT(16-19) cph0-cph3
 */
#define ADF_4XXX_SPPPARERRMSK_ATH_CPH_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(3) | \
	 BIT(16) | BIT(17) | BIT(18) | BIT(19))

/* Accelerator spp parity error mask
 * BIT(0)  cpr0
 * BIT(16) xlt0
 */
#define ADF_4XXX_SPPPARERRMSK_CPR_XLT_MASK (BIT(0) | BIT(16))

/* Accelerator spp parity error mask
 * BIT(0-2) dcpr0-dcpr2
 * BIT(16)  ucs0
 * BIT(17)  ucs1
 */
#define ADF_4XXX_SPPPARERRMSK_DCPR_UCS_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(16) | BIT(17))

/* Accelerator spp parity error mask
 * BIT(0-5) pke0-pke5
 */
#define ADF_4XXX_SPPPARERRMSK_PKE_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(4) | BIT(5))

/* RAS enabling related registers */
#define ADF_4XXX_SSMFEATREN(i) (0x198 + ((i) * 0x800))

/* Uncorrectable errors enabling related register mask
 * BIT(4)     Parity enable for CPP parity
 * BIT(7)     Parity enable for SSM RFs
 * BIT(13)    Bank uncorrectable ECC data errors
 * BIT(12)    Push/pull data errors
 * BIT(23-16) Parity enable for SPPs
 */
#define ADF_4XXX_SSMFEATREN_UE_MASK \
	(BIT(4) | BIT(7) | BIT(12) | BIT(13) | BIT(16) | BIT(17) | \
	 BIT(18) | BIT(19) | BIT(20) | BIT(21) | BIT(22) | BIT(23))

/* Correctable errors enabling related register mask
 * BIT(10)    Errors in bfmgrerror register
 * BIT(14)    ECC data errors
 * BIT(15)    Errors in rsrcmgrerror register
 */
#define ADF_4XXX_SSMFEATREN_CE_MASK (BIT(10) | BIT(14) | BIT(15))

/* This register has enable bits to enable SER detection in SER_err_ssmsh
 * register. When the enable bits are set, the Uncorrectable errors trigger
 * stop and scream, and the correctable errors trigger SSM interrupt.
 */
#define ADF_4XXX_SER_EN_SSMSH (0x450)

/* Uncorrectable errors mask - SER detection in SER_en_err_ssmsh
 * BIT(0) Enables uncorrectable Error detection in :
 *	  1) slice controller command RFs.
 *	  2) target push/pull data registers
 * BIT(2) Enables Parity error detection in
 *	  1) The bank SPP fifos
 *	  2) gen3_pull_id_queue
 *	  3) gen3_push_id_queue
 *	  4) ME_pull_sigdn_fifo
 *	  5) DT_push_sigdn_fifo
 *	  6) slx_push_sigdn_fifo
 *	  7) secure_push_cmd_fifo
 *	  8) secure_pull_cmd_fifo
 *	  9) Head register in FIFO wrapper
 *	  10) current_cmd in individual push queue
 *	  11) current_cmd in individual pull queue
 *	  12) push_command_rxp arbitrated in ssm_push_cmd_queues
 *	  13) pull_command_rxp arbitrated in ssm_pull_cmd_queues
 * BIT(3) Enables uncorrectable Error detection in
 *	  the Resource Manager mectx cmd RFs.
 * BIT(5) Enables Parity error detection in
 *	  1) Resource Manager lock request fifo
 *	  2) mectx cmdqueues logic
 *	  3) mectx sigdone fifo
 * BIT(6) Enables Parity error detection in Buffer Manager pools
 *	  and sigdone fifo
 *
 */
#define ADF_4XXX_SER_EN_SSMSH_UCERR_MASK \
	(BIT(0) | BIT(2) | BIT(3) | BIT(5) | BIT(6))

/* Correctable errors mask - SER detection in SER_en_err_ssmsh */
#define ADF_4XXX_SER_EN_SSMSH_CERR_MASK (BIT(1) | BIT(4))

/* Uncorrectable errors mask in INTMASKSSM
 * BIT(0) Shared Memory Uncorrectable Interrupt Mask
 * BIT(2) A value of 1 disables the PPERR interrupt
 * BIT(3) CPP Parity error Interrupt
 * BIT(5) SSM interrupt generated by SER Uncorrectable errors which are not
 *        stop and scream
 */
#define ADF_4XXX_INTMASKSSM_UE (BIT(0) | BIT(2) | BIT(3) | BIT(5))

/* Correctable errors mask in INTMASKSSM
 * BIT(1) masks correctable ECC interrupts
 * BIT(4) masks SSM interrupt generated by correctable errors
 */
#define ADF_4XXX_INTMASKSSM_CERR (BIT(1) | BIT(4))

/* Error source registers */
#define ADF_4XXX_ERRSOU0 (0x41A200)
#define ADF_4XXX_ERRSOU1 (0x41A204)
#define ADF_4XXX_ERRSOU2 (0x41A208)
#define ADF_4XXX_ERRSOU3 (0x41A20C)

/* Error source mask registers */
#define ADF_4XXX_ERRMSK0 (0x41A210)
#define ADF_4XXX_ERRMSK1 (0x41A214)
#define ADF_4XXX_ERRMSK2 (0x41A218)
#define ADF_4XXX_ERRMSK3 (0x41A21C)

/* Masks for correctable error interrupts. */
/* BIT(0) ORed AE Correctable Error Mask */
#define ADF_4XXX_ERRMSK0_CERR (BIT(0))
#define ADF_4XXX_ERRMSK1_CERR (0)

/* BIT(4) ORed AE Thread INTB Mask for CPP-0
 * BIT(3) ORed AE Thread INTA Mask for CPP-0
 */
#define ADF_4XXX_ERRMSK2_CERR (BIT(3) | BIT(4))

/* BIT(3) aRAM Correctable Error Mask */
#define ADF_4XXX_ERRMSK3_CERR (BIT(3))

/* Masks for uncorrectable error interrupts. */
#define ADF_4XXX_ERRMSK0_UERR (0)

/* BIT(4) IOSF Primary Command Parity error Mask
 * BIT(3) ORed TI Memory Parity Errors Mask
 * BIT(2) ORed RI Memory Parity Errors Mask
 * BIT(1) ORed CPP Command Parity Errors Mask
 * BIT(0) ORed AEx Uncorrectable Error Mask
 */
#define ADF_4XXX_ERRMSK1_UERR (BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(4))

/* BIT(0) SSM0 Interrupt Mask */
#define ADF_4XXX_ERRSOU2_CFC0_SSM0             BIT(0)
/* BIT(1) CFC on CPP0. ORed of CFC Push Error and Pull Error. */
#define ADF_4XXX_ERRSOU2_CFC0_PUSHPULL_ERR     BIT(1)
/* BIT(2) CFC on CPP0. ORed of Attention interrupt signals
 * from MEs routed through CFC
 */
#define ADF_4XXX_ERRSOU2_CFC0_ATTN_INT         BIT(2)

#define ADF_4XXX_ERRMSK2_UERR ( \
		(ADF_4XXX_ERRSOU2_CFC0_SSM0) | \
		(ADF_4XXX_ERRSOU2_CFC0_PUSHPULL_ERR) | \
		(ADF_4XXX_ERRSOU2_CFC0_ATTN_INT))

/* BIT(9) RLTERROR Mask for error source3
 * BIT(8) ATU fault Mask
 * BIT(6) RI Push parity error interrupt mask
 * BIT(5) TI Pull parity error interrupt mask
 * BIT(4) aRAM Uncorrectable Error Mask
 * BIT(2) TI ORed Push Pull Error Mask.
 * BIT(1) RI Push Pull error mask
 * BIT(0) This bit indicates the following error conditions:- FLR- BME
 */
#define ADF_4XXX_ERRMSK3_UERR \
(BIT(0) | BIT(1) | BIT(2) | BIT(4) | BIT(5) | BIT(6) | \
BIT(8) | BIT(9))

/* BIT(7) ORed 128 VFLR interrupts Mask */
#define ADF_4XXX_ERRMSK3_VFLRNOTIFY (BIT(7))

/* Buffer manager error status */
#define ADF_4XXX_BFMGRERROR (0x3E0)

/* Firmware error conditions in Resource Manager and Buffer Manager */
#define ADF_4XXX_FW_ERR_STATUS (0x440)

/*
 * RF parity error detected in SharedRAM.
 */
#define ADF_4XXX_SSMSOFTERRORPARITY_SRC_MASK (BIT(0))

/*
 * Fatal errors mask in SER_ERR_SSMSH
 * BIT(2)  A value of 1 indicates Parity error occurred in the bank SPP fifos
 * BIT(4)  A value of 1 indicates Parity error occurred in flops in the design
 * BIT(5) A value of 1 indicates an uncorrectable error has occurred in the
 *        target push and pull data register flop
 * BIT(7) A value of 1 indicates Parity error occurred in the Resource Manager
 *        pending lock request fifos
 * BIT(8) A value of 1 indicates Parity error occurred in the Resource Manager
 *        MECTX command queues logic
 * BIT(9) A value of 1 indicates Parity error occurred in the Resource Manager
 *        MECTX sigdone fifo flops
 * BIT(10) A value of 1 indicates an uncorrectable error has occurred in the
 *         Resource Manager MECTX command RFs
 * BIT(14) Parity error occurred in Buffer Manager sigdone FIFO
 */
 #define ADF_4XXX_SER_ERR_SSMSH_FATERR_MASK \
	 (BIT(2) | BIT(4) | BIT(5) | BIT(7) | BIT(8) | BIT(9) | \
	  BIT(10) | BIT(14))

/* Uncorrectable errors mask in SER_ERR_SSMSH
 * BIT(0)  A value of 1 indicates an uncorrectable error has occurred in the
 *         accelerator controller command RFs
 * BIT(3)  A value of 1 indicates Parity error occurred in following fifos in
 *         the design
 * BIT(12) Parity error occurred in Buffer Manager pool 0
 * BIT(13) Parity error occurred in Buffer Manager pool 1
 */
#define ADF_4XXX_SER_ERR_SSMSH_UCERR_MASK \
	(BIT(0) | BIT(3) | BIT(12) | BIT(13))

/* Correctable errors mask in SER_ERR_SSMSH
 * BIT(11) Correctable error has occurred in the Resource Manager MECTX command
 *         RFs
 * BIT(6)  Correctable error has occurred in the target push and pull data
 *         register flops
 * BIT(1)  Correctable error has occurred in the accelerator controller command
 *         RFs
 */
#define ADF_4XXX_SER_ERR_SSMSH_CERR_MASK \
	(BIT(1) | BIT(6) | BIT(11))

/* Error on CPP Push or Pull Transaction */
#define ADF_4XXX_PPERR (0x8)

/* PERR bit
 * BIT(0) Value of 1 indicates an uncorrectable error has been observed
 * BIT(1) Value of 1 indicates that more than one error has been observed
 */
#define ADF_4XXX_PPERR_PERR_MASK (BIT(0) | BIT(1))

/* UERRSSMSH uncorrectable errors mask
 * BIT(15) A value of 1 indicates that more than one Uncorrectable Error
 *         have occurred in the QAT shared memory.
 * BIT(0)  A value of 1 indicates an uncorrectable error has
 *         occurred in the QAT shared memory
 */
#define ADF_4XXX_UERRSSMSH_UERR_MASK \
		(BIT(0) | BIT(15))

/* Uncorrectable errors mask in SSMCPPERR
 * BIT(5) Value of 1 indicates CPP target pull data parity error
 * BIT(4) Value of 1 indicates CPP Main Pull PPID parity error
 * BIT(3) Value of 1 indicates CPP Main push data parity error
 * BIT(2) Value of 1 indicates CPP Main ePPID parity error
 * BIT(1) Value of 1 indicates CPP Main Push PPID parity error
 * BIT(0) Value of 1 indicates CPP command parity error
 */
#define ADF_4XXX_SSMCPPERR_UCERR_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(4) | BIT(5))

/* Exception Reporting in QAT SSM CMP */
#define ADF_4XXX_EXPRPSSMCPR (0x2000)

/* Uncorrectable errors mask in EXPRPSSMCPR
 *
 * BIT(26) Parity Error detected in CPR History Buffer Copy 7
 * BIT(25) Parity Error detected in CPR History Buffer Copy 6
 * BIT(24) Parity Error detected in CPR History Buffer Copy 5
 * BIT(23) Parity Error detected in CPR History Buffer Copy 4
 * BIT(22) Parity Error detected in CPR History Buffer Copy 3
 * BIT(21) Parity Error detected in CPR History Buffer Copy 2
 * BIT(20) Parity Error detected in CPR History Buffer Copy 1
 * BIT(19) Parity Error detected in CPR History Buffer Copy 0
 * BIT(18) Parity Error detected in CPR Hash Table
 * BIT(17) Parity Error detected in CPR Pull FIFO
 * BIT(16) Parity Error detected in CPR Push FIFO
 * BIT(3)  Block drop occurred for dynamic deflate compression
 * BIT(2)  Hard fatal error
 */
#define ADF_4XXX_EXPRPSSMCPR_UERR_MASK \
	(BIT(2) | BIT(3) | BIT(16) | BIT(17) | BIT(18) | BIT(19) | BIT(20) | \
	 BIT(21) | BIT(22) | BIT(23) | BIT(24) | BIT(25) | BIT(26))

/* Correctable errors mask in EXPRPSSMCPR
 * BIT(1) Notify event occurred (mapped to overflow condition)
 * BIT(4) LZ4 literal buffer overflow occurred
 * BIT(5) LZ4 Input Byte count overflow occurred
 * BIT(6) LZ4 Output Byte count overflow occurred
 */
#define ADF_4XXX_EXPRPSSMCPR_CERR_MASK \
	(BIT(1) | BIT(4) | BIT(5) | BIT(6))

/* Exception Reporting in QAT SSM XLT */
#define ADF_4XXX_EXPRPSSMXLT (0xA000)

/* Uncorrectable errors mask in EXPRPSSMXLT
 * BIT(23) Parity Error detected in XLT LITPTR
 * BIT(22) Parity Error detected in XLT CBCL
 * BIT(21) Parity Error detected in XLT HCTB3
 * BIT(20) Parity Error detected in XLT HCTB2
 * BIT(19) Parity Error detected in XLT HCTB1
 * BIT(18) Parity Error detected in XLT HCTB0
 * BIT(17) Parity Error detected in XLT Pull FIFO
 * BIT(16) Parity Error detected in XLT Push FIFO
 * BIT(2)  If set, an Uncorrectable Error event occurred
 */
#define ADF_4XXX_EXPRPSSMXLT_UERR_MASK \
	(BIT(2) | BIT(16) | BIT(17) | BIT(18) | BIT(19) | BIT(20) | BIT(21) | \
	 BIT(22) | BIT(23))

/* Correctable errors mask in EXPRPSSMXLT
 * BIT(1) Notify event occurred (mapped to overflow condition).
 * BIT(3) Correctable error event occurred.
 */
#define ADF_4XXX_EXPRPSSMXLT_CERR_MASK \
	(BIT(1) | BIT(3))

/* HI AE Uncorrectable Error Log */
#define ADF_4XXX_HIAEUNCERRLOG_CPP0 (0x41A300)

/* HI AE Uncorrectable Error Log mask
 * BIT(0-8) ME0-ME8 Uncorrectable Error
 */
#define ADF_4XXX_HIAEUNCERRLOG_CPP0_MASK (0x1FF)

/* HI AE Correctable Error Reporting Enable */
#define ADF_4XXX_HIAECORERRLOGENABLE_CPP0        (0x41A318)

/* QAT_4XXX has 9 AE. Enable logging for every AE */
#define ADF_4XXX_HIAECORERRLOGENABLE_CPP0_MASK   (0x00001FF)

/* HI AE Uncorrectable Error Reporting Enable */
#define ADF_4XXX_HIAEUNCERRLOGENABLE_CPP0 (0x41A320)

/* QAT_4XXX has 9 AE. Enable logging for every AE */
#define ADF_4XXX_HIAEUNCERRLOGENABLE_CPP0_MASK (0x00001FF)

/* HI CPP Agents Command parity Error Reporting Enable */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE                  (0x41A314)
#define ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_TICMDPARERR_MASK     BIT(0)
#define ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_RICMDPARERR_MASK     BIT(1)
#define ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_ARAMCMDPARERR_MASK   BIT(2)
#define ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_CFC0CMDPARERR_MASK   BIT(3)
#define ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_SSMCMDPARERR_MASK    BIT(4)

/* Error mask for HICPPAGENTCMDPARERRLOGENABLE register */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_MASK ( \
	ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_TICMDPARERR_MASK | \
	ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_RICMDPARERR_MASK | \
	ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_ARAMCMDPARERR_MASK | \
	ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_CFC0CMDPARERR_MASK | \
	ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_SSMCMDPARERR_MASK)

/* RI Misc Control Register */
#define ADF_4XXX_RIMISCCTL                       (0x41B1BC)

/* Mask for RIMISCCTL register
 * BIT(0) enables IOSF Primary Command Parity error reporting
 */
#define ADF_4XXX_RIMISCCTL_MASK                  (BIT(0))

/* Clock Gating Control IOSF Primary Register */
#define ADF_4XXX_PFCGC_IOSF_PRIR                 (0x2C0)

/* BIT(16) Parity Check Enable */
#define ADF_4XXX_PFCGC_IOSF_PRIR_MASK            (BIT(16))

/* RI Memory Parity Error Enable Register */
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0                            (0x41B12C)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ0_MASK    BIT(0)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ1_MASK    BIT(1)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ2_MASK    BIT(2)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ3_MASK    BIT(3)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_PHDR_MASK           BIT(4)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_PDATA_MASK          BIT(5)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_NPHDR_MASK          BIT(6)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_NPDATA_MASK         BIT(7)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLHDR0_MASK        BIT(8)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLHDR1_MASK        BIT(9)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA0_MASK       BIT(10)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA1_MASK       BIT(11)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA2_MASK       BIT(12)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA3_MASK       BIT(13)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA4_MASK       BIT(14)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA5_MASK       BIT(15)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA6_MASK       BIT(16)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA7_MASK       BIT(17)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CDTRET_MASK         BIT(18)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_CDS_CMD_FIFO_MASK       BIT(19)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_RICPL_FIFO_MASK     BIT(20)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_TIRICPL_FIFO_MASK   BIT(21)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_CPP0CPL_FIFO_MASK   BIT(22)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_PENDCPL_FIFO_MASK   BIT(23)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_CPP_CMD_FIFO_MASK       BIT(24)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_CDS_TICMD_FIFO_MASK     BIT(25)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RITI_CMD_FIFO_MASK         BIT(26)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_INT_MSIXTBL_MASK        BIT(27)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_INT_IMSTBL_MASK         BIT(28)
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_KPT_FUSES_MASK          BIT(30)

/* Error mask RI_MEM_PAR_ERR_EN0 register */
#define ADF_4XXX_RI_MEM_PAR_ERR_EN0_UC_MASK ( \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ0_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ1_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ2_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_IOSF_PDATA_RXQ3_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_PHDR_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_PDATA_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_NPHDR_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_NPDATA_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLHDR0_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLHDR1_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA0_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA1_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA2_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA3_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA4_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA5_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA6_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CPLDATA7_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_TLQ_CDTRET_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_CDS_CMD_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_RICPL_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_TIRICPL_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_CPP0CPL_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_OBC_PENDCPL_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_CPP_CMD_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_CDS_TICMD_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RITI_CMD_FIFO_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_INT_MSIXTBL_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_INT_IMSTBL_MASK) | \
		 (ADF_4XXX_RI_MEM_PAR_ERR_EN0_RI_KPT_FUSES_MASK))

/* RI Memory Parity Error First Error */
#define ADF_4XXX_RI_MEM_PAR_ERR_FERR (0x41B130)

/* RI Memory Parity Error Status Register */
#define ADF_4XXX_RIMEM_PARERR_STS (0x41B128)

/* Parity Reporting Disable/Error mask for CdCmdQ */
#define ADF_4XXX_TI_CI_PAR_ERR_CDCMDQ		BIT(0)
/* Parity Reporting Disable/Error mask for CdDataQ */
#define ADF_4XXX_TI_CI_PAR_ERR_CDDATAQ		BIT(1)
/* Parity Reporting Disable/Error mask for PullDataSrcQ_rsvd */
#define ADF_4XXX_TI_CI_PAR_ERR_PULLDATASRCQ	BIT(2)
/* Parity Reporting Disable/Error mask for CPP0_SkidQ */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP0_SKIDQ	BIT(3)
/* Parity Reporting Disable/Error mask for CPP1_SkidQ */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP1_SKIDQ	BIT(4)
/* Parity Reporting Disable/Error mask for CPP2_SkidQ */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP2_SKIDQ	BIT(5)
/* Parity Reporting Disable/Error mask for CPP3_SkidQ */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP3_SKIDQ	BIT(6)
/* Parity Reporting Disable/Error mask for CPP0_SkidQ_sc */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP0_SKIDQ_SC	BIT(7)
/* Parity Reporting Disable/Error mask for CPP1_SkidQ_sc */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP1_SKIDQ_SC	BIT(8)
/* Parity Reporting Disable/Error mask for CPP2_SkidQ_sc */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP2_SKIDQ_SC	BIT(9)
/* Parity Reporting Disable/Error mask for CPP3_SkidQ_sc */
#define ADF_4XXX_TI_CI_PAR_ERR_CPP3_SKIDQ_SC	BIT(10)

/* Error mask for Parity Reporting Disable register
 * ADF_4XXX_TI_CI_PAR_ERR_MASK
 */
#define ADF_4XXX_TI_CI_PAR_ERR_RW_BITMASK ( \
		(ADF_4XXX_TI_CI_PAR_ERR_CDCMDQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CDDATAQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP0_SKIDQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP0_SKIDQ_SC))

/* Error mask for Parity Reporting Status register
 * ADF_4XXX_TI_CI_PAR_STS
 */
#define ADF_4XXX_TI_CI_PAR_ERR_BITMASK ( \
		(ADF_4XXX_TI_CI_PAR_ERR_CDCMDQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CDDATAQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_PULLDATASRCQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP0_SKIDQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP1_SKIDQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP2_SKIDQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP3_SKIDQ) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP0_SKIDQ_SC) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP1_SKIDQ_SC) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP2_SKIDQ_SC) | \
		(ADF_4XXX_TI_CI_PAR_ERR_CPP3_SKIDQ_SC))

/* Parity Reporting Disable/Error mask for TrnPullReqQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNPULLREQQ	BIT(0)
/* Parity Reporting Disable/Error mask for TrnSharedDataQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNSHAREDDATAQ	BIT(1)
/* Parity Reporting Disable/Error mask for TrnPullReqDataQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNPULLREQDATAQ	BIT(2)
/* Parity Reporting Disable/Error mask for CPP0_CiPullReqQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_CIPULLREQQ	BIT(4)
/* Parity Reporting Disable/Error mask for CPP0_TrnPullReqQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNPULLREQQ	BIT(5)
/* Parity Reporting Disable/Error mask for CPP0_PullidQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_PULLIDQ	BIT(6)
/* Parity Reporting Disable/Error mask for CPP0_WaitDataQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_WAITDATAQ	BIT(7)
/* Parity Reporting Disable/Error mask for CPP0_CdDataQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_CDDATAQ	BIT(8)
/* Parity Reporting Disable/Error mask for CPP0_TrnDataQP0 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQP0	BIT(9)
/* Parity Reporting Disable/Error mask for CPP0_TrnDataQRF00 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF00	BIT(10)
/* Parity Reporting Disable/Error mask for CPP0_TrnDataQRF01 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF01	BIT(11)
/* Parity Reporting Disable/Error mask for CPP0_TrnDataQP1 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQP1	BIT(12)
/* Parity Reporting Disable/Error mask for CPP0_TrnDataQRF10 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF10	BIT(13)
/* Parity Reporting Disable/Error mask for CPP0_TrnDataQRF11 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF11	BIT(14)
/* Parity Reporting Disable/Error mask for CPP1_CiPullReqQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_CIPULLREQQ	BIT(16)
/* Parity Reporting Disable/Error mask for CPP1_TrnPullReqQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNPULLREQQ	BIT(17)
/* Parity Reporting Disable/Error mask for CPP1_PullidQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_PULLIDQ	BIT(18)
/* Parity Reporting Disable/Error mask for CPP1_WaitDataQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_WAITDATAQ	BIT(19)
/* Parity Reporting Disable/Error mask for CPP1_CdDataQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_CDDATAQ	BIT(20)
/* Parity Reporting Disable/Error mask for CPP1_TrnDataQP0 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQP0	BIT(21)
/* Parity Reporting Disable/Error mask for CPP1_TrnDataQRF00 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF00	BIT(22)
/* Parity Reporting Disable/Error mask for CPP1_TrnDataQRF01 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF01	BIT(23)
/* Parity Reporting Disable/Error mask for CPP1_TrnDataQP1 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQP1	BIT(24)
/* Parity Reporting Disable/Error mask for CPP1_TrnDataQRF10 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF10	BIT(25)
/* Parity Reporting Disable/Error mask for CPP1_TrnDataQRF11 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF11	BIT(26)
/* Parity Reporting Disable/Error mask for CPP2_CiPullReqQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_CIPULLREQQ	BIT(28)
/* Parity Reporting Disable/Error mask for CPP2_TrnPullReqQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_TRNPULLREQQ	BIT(29)
/* Parity Reporting Disable/Error mask for CPP2_PullidQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_PULLIDQ	BIT(30)
/* Parity Reporting Disable/Error mask for CPP2_WaitDataQ */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_WAITDATAQ	BIT(31)

/* Error mask for Parity Reporting Disable register
 * ADF_4XXX_TI_PULL0FUB_PAR_ERR_MASK
 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_RW_BITMASK ( \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNSHAREDDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNPULLREQDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_CIPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_PULLIDQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_WAITDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_CDDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQP0) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF00) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF01) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQP1) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF10) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF11))

/* Error mask for Parity Reporting Status register
 * ADF_4XXX_TI_PULL0FUB_PAR_STS
 */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_BITMASK ( \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNSHAREDDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_TRNPULLREQDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_CIPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_PULLIDQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_WAITDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_CDDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQP0) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF00) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF01) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQP1) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF10) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP0_TRNDATAQRF11) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_CIPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_PULLIDQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_WAITDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_CDDATAQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQP0) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF00) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF01) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQP1) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF10) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP1_TRNDATAQRF11) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_CIPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_TRNPULLREQQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_PULLIDQ) | \
		(ADF_4XXX_TI_PULL0FUB_PAR_ERR_CPP2_WAITDATAQ))

/* Parity Reporting Disable/Error mask for SbPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHREQQ		BIT(0)
/* Parity Reporting Disable/Error mask for SbPushDataQ0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHDATAQ0	BIT(1)
/* Parity Reporting Disable/Error mask for SbPushDataQ1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHDATAQ1	BIT(2)
/* Parity Reporting Disable/Error mask for CPP0_CdPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHREQQ	BIT(4)
/* Parity Reporting Disable/Error mask for CPP0_CdPushDataQ0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHDATAQ0	BIT(5)
/* Parity Reporting Disable/Error mask for CPP0_CdPushDataQ1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHDATAQ1	BIT(6)
/* Parity Reporting Disable/Error mask for CPP0_SbPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHREQQ	BIT(7)
/* Parity Reporting Disable/Error mask for CPP0_SbPushDataQP. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQP	BIT(8)
/* Parity Reporting Disable/Error mask for CPP0_SbPushDataQRF0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQRF0	BIT(9)
/* Parity Reporting Disable/Error mask for CPP0_SbPushDataQRF1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQRF1	BIT(10)
/* Parity Reporting Disable/Error mask for CPP1_CdPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_CDPUSHREQQ	BIT(11)
/* Parity Reporting Disable/Error mask for CPP1_CdPushDataQ0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_CDPUSHDATAQ0	BIT(12)
/* Parity Reporting Disable/Error mask for CPP1_CdPushDataQ1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_CDPUSHDATAQ1	BIT(13)
/* Parity Reporting Disable/Error mask for CPP1_SbPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHREQQ	BIT(14)
/* Parity Reporting Disable/Error mask for CPP1_SbPushDataQP. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHDATAQP	BIT(15)
/* Parity Reporting Disable/Error mask for CPP1_SbPushDataQRF0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHDATAQRF0	BIT(16)
/* Parity Reporting Disable/Error mask for CPP1_SbPushDataQRF1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHDATAQRF1	BIT(17)
/* Parity Reporting Disable/Error mask for CPP2_CdPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_CDPUSHREQQ	BIT(18)
/* Parity Reporting Disable/Error mask for CPP2_CdPushDataQ0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_CDPUSHDATAQ0	BIT(19)
/* Parity Reporting Disable/Error mask for CPP2_CdPushDataQ1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_CDPUSHDATAQ1	BIT(20)
/* Parity Reporting Disable/Error mask for CPP2_SbPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHREQQ	BIT(21)
/* Parity Reporting Disable/Error mask for CPP2_SbPushDataQP. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHDATAQP	BIT(22)
/* Parity Reporting Disable/Error mask for CPP2_SbPushDataQRF0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHDATAQRF0	BIT(23)
/* Parity Reporting Disable/Error mask for CPP2_SbPushDataQRF1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHDATAQRF1	BIT(24)
/* Parity Reporting Disable/Error mask for CPP3_CdPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_CDPUSHREQQ	BIT(25)
/* Parity Reporting Disable/Error mask for CPP3_CdPushDataQ0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_CDPUSHDATAQ0	BIT(26)
/* Parity Reporting Disable/Error mask for CPP3_CdPushDataQ1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_CDPUSHDATAQ1	BIT(27)
/* Parity Reporting Disable/Error mask for CPP3_SbPushReqQ. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHREQQ	BIT(28)
/* Parity Reporting Disable/Error mask for CPP3_SbPushDataQP. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHDATAQP	BIT(29)
/* Parity Reporting Disable/Error mask for CPP3_SbPushDataQRF0. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHDATAQRF0	BIT(30)
/* Parity Reporting Disable/Error mask for CPP3_SbPushDataQRF1. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHDATAQRF1	BIT(31)

/* Error mask for Parity Reporting Disable register
 * ADF_4XXX_TI_PUSHFUB_PAR_ERR_MASK
 */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_RW_BITMASK ( \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHDATAQ0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHDATAQ1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHDATAQ0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHDATAQ1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQP) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQRF0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQRF1))

/* Error mask for Parity Reporting Status register
 * ADF_4XXX_TI_PUSHFUB_PAR_STS
 */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_BITMASK ( \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHDATAQ0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_SBPUSHDATAQ1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHDATAQ0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_CDPUSHDATAQ1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQP) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQRF0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP0_SBPUSHDATAQRF1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_CDPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_CDPUSHDATAQ0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_CDPUSHDATAQ1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHDATAQP) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHDATAQRF0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP1_SBPUSHDATAQRF1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_CDPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_CDPUSHDATAQ0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_CDPUSHDATAQ1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHDATAQP) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHDATAQRF0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP2_SBPUSHDATAQRF1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_CDPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_CDPUSHDATAQ0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_CDPUSHDATAQ1) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHREQQ) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHDATAQP) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHDATAQRF0) | \
		(ADF_4XXX_TI_PUSHFUB_PAR_ERR_CPP3_SBPUSHDATAQRF1))

/* Parity Reporting Disable/Error mask for CtxMdRam(0-15) */
#define ADF_4XXX_TI_CD_PAR_ERR_CTXMDRAM		(0xFFFF)
/* Parity Reporting Disable/Error mask for Leaf2ClusterRam. */
#define ADF_4XXX_TI_CD_PAR_ERR_LEAF2CLUSTERRAM	BIT(16)
/* Parity Reporting Disable/Error mask for Ring2LeafRam0. */
#define ADF_4XXX_TI_CD_PAR_ERR_RING2LEAFRAM0	BIT(17)
/* Parity Reporting Disable/Error mask for Ring2LeafRam1. */
#define ADF_4XXX_TI_CD_PAR_ERR_RING2LEAFRAM1	BIT(18)
/* Parity Reporting Disable/Error mask for VirtualQ. */
#define ADF_4XXX_TI_CD_PAR_ERR_VIRTUALQ		BIT(19)
/* Parity Reporting Disable/Error mask for DtRdQ */
#define ADF_4XXX_TI_CD_PAR_ERR_DTRDQ		BIT(20)
/* Parity Reporting Disable/Error mask for DtWrQ. */
#define ADF_4XXX_TI_CD_PAR_ERR_DTWRQ		BIT(21)
/* Parity Reporting Disable/Error mask for RiCmdQ. */
#define ADF_4XXX_TI_CD_PAR_ERR_RICMDQ		BIT(22)
/* Parity Reporting Disable/Error mask for BypassQ. */
#define ADF_4XXX_TI_CD_PAR_ERR_BYPASSQ		BIT(23)
/* Parity Reporting Disable/Error mask for DtRdQ_sc. */
#define ADF_4XXX_TI_CD_PAR_ERR_DTRDQ_SC		BIT(24)
/* Parity Reporting Disable/Error mask for DtWrQ_sc. */
#define ADF_4XXX_TI_CD_PAR_ERR_DTWRQ_SC		BIT(25)

/* Error mask for Parity Reporting Disable/Status registers
 * ADF_4XXX_TI_CD_PAR_ERR_MASK and ADF_4XXX_TI_CD_PAR_STS
 */
#define ADF_4XXX_TI_CD_PAR_ERR_BITMASK ( \
		(ADF_4XXX_TI_CD_PAR_ERR_CTXMDRAM) | \
		(ADF_4XXX_TI_CD_PAR_ERR_LEAF2CLUSTERRAM) | \
		(ADF_4XXX_TI_CD_PAR_ERR_RING2LEAFRAM0) | \
		(ADF_4XXX_TI_CD_PAR_ERR_RING2LEAFRAM1) | \
		(ADF_4XXX_TI_CD_PAR_ERR_VIRTUALQ) | \
		(ADF_4XXX_TI_CD_PAR_ERR_DTRDQ) | \
		(ADF_4XXX_TI_CD_PAR_ERR_DTWRQ) | \
		(ADF_4XXX_TI_CD_PAR_ERR_RICMDQ) | \
		(ADF_4XXX_TI_CD_PAR_ERR_BYPASSQ) | \
		(ADF_4XXX_TI_CD_PAR_ERR_DTRDQ_SC) | \
		(ADF_4XXX_TI_CD_PAR_ERR_DTWRQ_SC))

/* Parity Reporting Disable/Error mask for TrnPHdrQP. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPHDRQP		BIT(0)
/* Parity Reporting Disable/Error mask for TrnPHdrQRF. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPHDRQRF		BIT(1)
/* Parity Reporting Disable/Error mask for TrnPDataQP. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQP		BIT(2)
/* Parity Reporting Disable/Error mask for TrnPDataQRF0. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF0		BIT(3)
/* Parity Reporting Disable/Error mask for TrnPDataQRF1. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF1		BIT(4)
/* Parity Reporting Disable/Error mask for TrnPDataQRF2. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF2		BIT(5)
/* Parity Reporting Disable/Error mask for TrnPDataQRF3. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF3		BIT(6)
/* Parity Reporting Disable/Error mask for TrnNpHdrQP. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNNPHDRQP		BIT(7)
/* Parity Reporting Disable/Error mask for TrnNpHdrQRF0. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNNPHDRQRF0		BIT(8)
/* Parity Reporting Disable/Error mask for TrnNpHdrQRF1. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNNPHDRQRF1		BIT(9)
/* Parity Reporting Disable/Error mask for TrnCplHdrQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNCPLHDRQ		BIT(10)
/* Parity Reporting Disable/Error mask for TrnPutObsReqQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPUTOBSREQQ		BIT(11)
/* Parity Reporting Disable/Error mask for TrnPushReqQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPUSHREQQ		BIT(12)
/* Parity Reporting Disable/Error mask for SbSplitIdRam. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBSPLITIDRAM		BIT(13)
/* Parity Reporting Disable/Error mask for SbReqCountQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBREQCOUNTQ		BIT(14)
/* Parity Reporting Disable/Error mask for SbCplTrkRam. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBCPLTRKRAM		BIT(15)
/* Parity Reporting Disable/Error mask for SbGetObsReqQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBGETOBSREQQ		BIT(16)
/* Parity Reporting Disable/Error mask for SbEpochIdQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBEPOCHIDQ		BIT(17)
/* Parity Reporting Disable/Error mask for SbAtCplHdrQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBATCPLHDRQ		BIT(18)
/* Parity Reporting Disable/Error mask for SbAtCplDataQ. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBATCPLDATAQ		BIT(19)
/* Parity Reporting Disable/Error mask for SbReqCountRam. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBREQCOUNTRAM		BIT(20)
/* Parity Reporting Disable/Error mask for SbAtCplHdrQ_sc. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_SBATCPLHDRQ_SC	BIT(21)

/* Error mask for Parity Reporting Disable/Status registers
 * ADF_4XXX_TI_TRNSB_PAR_ERR_MASK and ADF_4XXX_TI_TRNSB_PAR_STS
 */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_BITMASK ( \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPHDRQP) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPHDRQRF) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQP) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF0) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF1) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF2) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPDATAQRF3) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNNPHDRQP) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNNPHDRQRF0) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNNPHDRQRF1) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNCPLHDRQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPUTOBSREQQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_TRNPUSHREQQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBSPLITIDRAM) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBREQCOUNTQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBCPLTRKRAM) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBGETOBSREQQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBEPOCHIDQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBATCPLHDRQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBATCPLDATAQ) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBREQCOUNTRAM) | \
		(ADF_4XXX_TI_TRNSB_PAR_ERR_SBATCPLHDRQ_SC))

/* Parity Reporting Disable/Error mask for MeExeRam. */
#define ADF_4XXX_RL_PAR_ERR_MEEXERAM		BIT(0)
/* Parity Reporting Disable/Error mask for SliceExeRam. */
#define ADF_4XXX_RL_PAR_ERR_SLICEEXERAM		BIT(1)
/* Parity Reporting Disable/Error mask for PCIeInRam. */
#define ADF_4XXX_RL_PAR_ERR_PCIEINRAM		BIT(2)
/* Parity Reporting Disable/Error mask for PCIeOutRam. */
#define ADF_4XXX_RL_PAR_ERR_PCIEOUTRAM		BIT(3)

/* Error mask for Parity Reporting Disable/Status registers
 * ADF_4XXX_RL_PAR_ERR_MASK and ADF_4XXX_RL_PAR_STS
 */
#define ADF_4XXX_RL_PAR_ERR_BITMASK ( \
		(ADF_4XXX_RL_PAR_ERR_MEEXERAM) | \
		(ADF_4XXX_RL_PAR_ERR_SLICEEXERAM) | \
		(ADF_4XXX_RL_PAR_ERR_PCIEINRAM) | \
		(ADF_4XXX_RL_PAR_ERR_PCIEOUTRAM))

/* Parity Reporting Disable/Error mask for ReqRingRam. */
#define ADF_4XXX_QM_PAR_ERR_REQRINGRAM		BIT(0)
/* Parity Reporting Disable/Error mask for RespRingRam. */
#define ADF_4XXX_QM_PAR_ERR_RESPRINGRAM		BIT(1)
/* Parity Reporting Disable/Error mask for QmRam. */
#define ADF_4XXX_QM_PAR_ERR_QMRAM		BIT(2)
/* Parity Reporting Disable/Error mask for ReqTllRam. */
#define ADF_4XXX_QM_PAR_ERR_REQTLLRAM		BIT(3)
/* Parity Reporting Disable/Error mask for RespTllRam. */
#define ADF_4XXX_QM_PAR_ERR_RESPTLLRAM		BIT(4)
/* Parity Reporting Disable/Error mask for EnqHdrQ. */
#define ADF_4XXX_QM_PAR_ERR_ENQHDRQ		BIT(5)
/* Parity Reporting Disable/Error mask for EnqDataQ. */
#define ADF_4XXX_QM_PAR_ERR_ENQDATAQ		BIT(6)
/* Parity Reporting Disable/Error mask for SqRam. */
#define ADF_4XXX_QM_PAR_ERR_SQRAM		BIT(7)
/* Parity Reporting Disable/Error mask for SqTllRam. */
#define ADF_4XXX_QM_PAR_ERR_SQTLLRAM		BIT(8)
/* Parity Reporting Disable/Error mask for SqLlmRam. */
#define ADF_4XXX_QM_PAR_ERR_SQLLMRAM		BIT(9)
/* Parity Reporting Disable/Error mask for DescFetchQ. */
#define ADF_4XXX_QM_PAR_ERR_DESCFETCHQ		BIT(10)
/* Parity Reporting Disable/Error mask for SteerBypassQ. */
#define ADF_4XXX_QM_PAR_ERR_STEERBYPASSQ	BIT(11)
/* Parity Reporting Disable/Error mask for SteerCSRQ. */
#define ADF_4XXX_QM_PAR_ERR_STEERCSRQ		BIT(12)
/* Parity Reporting Disable/Error mask for SteerRingQ. */
#define ADF_4XXX_QM_PAR_ERR_STEERRINGQ		BIT(13)
/* Parity Reporting Disable/Error mask for CTXRam. */
#define ADF_4XXX_QM_PAR_ERR_CTXRAM		BIT(14)
/* Parity Reporting Disable/Error mask for CCExitQ. */
#define ADF_4XXX_QM_PAR_ERR_CCEXITQ		BIT(15)
/* Parity Reporting Disable/Error mask for RCExitQ. */
#define ADF_4XXX_QM_PAR_ERR_RCEXITQ		BIT(16)
/* Parity Reporting Disable/Error mask for RCPushQ. */
#define ADF_4XXX_QM_PAR_ERR_RCPUSHQ		BIT(17)
/* Parity Reporting Disable/Error mask for ReqTLLFeedQ. */
#define ADF_4XXX_QM_PAR_ERR_REQTLLFEEDQ		BIT(18)
/* Parity Reporting Disable/Error mask for RespTLLFeedQ. */
#define ADF_4XXX_QM_PAR_ERR_RESPTLLFEEDQ	BIT(19)

/* Error mask for Parity Reporting Disable/Status registers
 * ADF_4XXX_QM_PAR_ERR_MASK and ADF_4XXX_QM_PAR_STS
 */
#define ADF_4XXX_QM_PAR_ERR_BITMASK ( \
		(ADF_4XXX_QM_PAR_ERR_REQRINGRAM) | \
		(ADF_4XXX_QM_PAR_ERR_RESPRINGRAM) | \
		(ADF_4XXX_QM_PAR_ERR_QMRAM) | \
		(ADF_4XXX_QM_PAR_ERR_REQTLLRAM) | \
		(ADF_4XXX_QM_PAR_ERR_RESPTLLRAM) | \
		(ADF_4XXX_QM_PAR_ERR_ENQHDRQ) | \
		(ADF_4XXX_QM_PAR_ERR_ENQDATAQ) | \
		(ADF_4XXX_QM_PAR_ERR_SQRAM) | \
		(ADF_4XXX_QM_PAR_ERR_SQTLLRAM) | \
		(ADF_4XXX_QM_PAR_ERR_SQLLMRAM) | \
		(ADF_4XXX_QM_PAR_ERR_DESCFETCHQ) | \
		(ADF_4XXX_QM_PAR_ERR_STEERBYPASSQ) | \
		(ADF_4XXX_QM_PAR_ERR_STEERCSRQ) | \
		(ADF_4XXX_QM_PAR_ERR_STEERRINGQ) | \
		(ADF_4XXX_QM_PAR_ERR_CTXRAM) | \
		(ADF_4XXX_QM_PAR_ERR_CCEXITQ) | \
		(ADF_4XXX_QM_PAR_ERR_RCEXITQ) | \
		(ADF_4XXX_QM_PAR_ERR_RCPUSHQ) | \
		(ADF_4XXX_QM_PAR_ERR_REQTLLFEEDQ) | \
		(ADF_4XXX_QM_PAR_ERR_RESPTLLFEEDQ))

/* TI Misc Control Register */
#define ADF_4XXX_TIMISCCTL                       (0x500548)
#define ADF_4XXX_TIMISCCTL_ERREN_MASK            BIT(0)
#define ADF_4XXX_TIMISCCTL_VF_RMAP_EN_MASK       BIT(1)
#define ADF_4XXX_TIMISCCTL_DISARB_CNTEN_MASK     BIT(2)
#define ADF_4XXX_TIMISCCTL_DISVFLR_MASK          BIT(30)
#define ADF_4XXX_TIMISCCTL_DIS_AE_AUTOPUSH_MASK  BIT(31)

/* Mask for TIMISCCTL register */
#define ADF_4XXX_TIMISCCTL_MASK (ADF_4XXX_TIMISCCTL_ERREN_MASK | \
		ADF_4XXX_TIMISCCTL_VF_RMAP_EN_MASK | \
		ADF_4XXX_TIMISCCTL_DISARB_CNTEN_MASK | \
		ADF_4XXX_TIMISCCTL_DISVFLR_MASK | \
		ADF_4XXX_TIMISCCTL_DIS_AE_AUTOPUSH_MASK)

/* TI Misc Status Register */
#define ADF_4XXX_TIMISCSTS   (0x50054C)

/* Uncorrectable error flags in errsou1 register */
#define ADF_4XXX_ERRSOU1_CPP0_AEUNC_MASK        BIT(0)
#define ADF_4XXX_ERRSOU1_CPPCMDPARERR_MASK      BIT(1)
#define ADF_4XXX_ERRSOU1_RI_MEM_PAR_ERR_MASK    BIT(2)
#define ADF_4XXX_ERRSOU1_TI_MEM_PAR_ERR_MASK    BIT(3)
#define ADF_4XXX_ERRSOU1_IOSFP_CMD_PARERR_MASK  BIT(4)

/* mask of uncorrectable errors in errsou1 register*/
#define ADF_4XXX_ERRSOU1_MASK (ADF_4XXX_ERRSOU1_CPP0_AEUNC_MASK | \
		ADF_4XXX_ERRSOU1_CPPCMDPARERR_MASK | \
		ADF_4XXX_ERRSOU1_RI_MEM_PAR_ERR_MASK | \
		ADF_4XXX_ERRSOU1_TI_MEM_PAR_ERR_MASK | \
		ADF_4XXX_ERRSOU1_IOSFP_CMD_PARERR_MASK)

/* Uncorrectable error flags in intstatssm register */
#define ADF_4XXX_INTSTATSSM_SH_UERR_MASK        BIT(0)
#define ADF_4XXX_INTSTATSSM_PPERR_MASK          BIT(2)
#define ADF_4XXX_INTSTATSSM_SPPPAR_ERR_MASK     BIT(4)
#define ADF_4XXX_INTSTATSSM_CPPPAR_ERR_MASK     BIT(5)
#define ADF_4XXX_INTSTATSSM_RFPAR_ERR_MASK      BIT(6)
#define ADF_4XXX_INTSTATSSM_SER_UERR_MASK       BIT(8)

/* mask of uncorrectable errors in interrupt status register */
#define ADF_4XXX_INTSTATSSM_MASK (ADF_4XXX_INTSTATSSM_SH_UERR_MASK | \
		ADF_4XXX_INTSTATSSM_PPERR_MASK | \
		ADF_4XXX_INTSTATSSM_SPPPAR_ERR_MASK | \
		ADF_4XXX_INTSTATSSM_CPPPAR_ERR_MASK | \
		ADF_4XXX_INTSTATSSM_RFPAR_ERR_MASK | \
		ADF_4XXX_INTSTATSSM_SER_UERR_MASK)

/* Uncorrectable error flags in errsou3 register */
#define ADF_4XXX_ERRSOU3_TIMISC_MASK          BIT(0)
#define ADF_4XXX_ERRSOU3_RIPUSHPULLERR_MASK   BIT(1)
#define ADF_4XXX_ERRSOU3_TIPUSHPULLERR_MASK   BIT(2)
#define ADF_4XXX_ERRSOU3_ARAM_UNCERR_MASK     BIT(4)
#define ADF_4XXX_ERRSOU3_TIPULLPARERR_MASK    BIT(5)
#define ADF_4XXX_ERRSOU3_RIPUSHPARERR_MASK    BIT(6)
#define ADF_4XXX_ERRSOU3_ATUFAULTNOTIFY_MASK  BIT(8)
#define ADF_4XXX_ERRSOU3_RLTERROR_MASK        BIT(9)

#define ADF_4XXX_RI_PPP_ERR_MASK \
	((ADF_4XXX_ERRSOU3_RIPUSHPULLERR_MASK) | \
	(ADF_4XXX_ERRSOU3_RIPUSHPARERR_MASK))

#define ADF_4XXX_TI_PPP_ERR_MASK \
	((ADF_4XXX_ERRSOU3_TIPUSHPULLERR_MASK) | \
	(ADF_4XXX_ERRSOU3_TIPULLPARERR_MASK))

/* mask of uncorrectable errors in errsou3 register*/
#define ADF_4XXX_ERRSOU3_MASK ((ADF_4XXX_ERRSOU3_TIMISC_MASK) | \
		(ADF_4XXX_ERRSOU3_RIPUSHPULLERR_MASK) | \
		(ADF_4XXX_ERRSOU3_TIPUSHPULLERR_MASK) | \
		(ADF_4XXX_ERRSOU3_ARAM_UNCERR_MASK) | \
		(ADF_4XXX_ERRSOU3_TIPULLPARERR_MASK) | \
		(ADF_4XXX_ERRSOU3_RIPUSHPARERR_MASK) | \
		(ADF_4XXX_ERRSOU3_ATUFAULTNOTIFY_MASK) | \
		(ADF_4XXX_ERRSOU3_RLTERROR_MASK))

/* Uncorrectable error flags in iaintstatssm register */
#define ADF_4XXX_IAINTSTATSSM_SH_UERR_MASK        BIT(0)
#define ADF_4XXX_IAINTSTATSSM_PPERR_MASK          BIT(2)
#define ADF_4XXX_IAINTSTATSSM_SLICEHANG_ERR_MASK  BIT(3)
#define ADF_4XXX_IAINTSTATSSM_SPPPAR_ERR_MASK     BIT(4)
#define ADF_4XXX_IAINTSTATSSM_CPPPAR_ERR_MASK     BIT(5)
#define ADF_4XXX_IAINTSTATSSM_RFPAR_ERR_MASK      BIT(6)
#define ADF_4XXX_IAINTSTATSSM_SER_UERR_MASK       BIT(8)

/* Correctable error flags in iaintstatssm register */
#define ADF_4XXX_IAINTSTATSSM_SH_CERR_MASK        BIT(1)
#define ADF_4XXX_IAINTSTATSSM_SER_CERR_MASK       BIT(7)

/* Mask of uncorrectable errors in interrupt status register */
#define ADF_4XXX_IAINTSTATSSM_UE_MASK ( \
		(ADF_4XXX_IAINTSTATSSM_SH_UERR_MASK) | \
		(ADF_4XXX_IAINTSTATSSM_PPERR_MASK) | \
		(ADF_4XXX_IAINTSTATSSM_SLICEHANG_ERR_MASK) | \
		(ADF_4XXX_IAINTSTATSSM_SPPPAR_ERR_MASK) | \
		(ADF_4XXX_IAINTSTATSSM_CPPPAR_ERR_MASK) | \
		(ADF_4XXX_IAINTSTATSSM_RFPAR_ERR_MASK) | \
		(ADF_4XXX_IAINTSTATSSM_SER_UERR_MASK))

/* VF function-level reset notify flag in errsou3 register */
#define ADF_4XXX_ERRSOU3_VFLRNOTIFY_MASK      (BIT(7))

#define ADF_4XXX_TIMISCSTS_ERR_MASK            BIT(0)

/* Mask for indication of the error type when the ERR bit is set
 * BIT(2) TI Internal uncorrectable - fatal error
 * BIT(1) CPP command parity error detected
 */
#define ADF_4XXX_TIMISCSTS_ERRTYPE_MASK        (BIT(2) | BIT(1))

#define ADF_4XXX_TIMISCSTS_MASK (ADF_4XXX_TIMISCSTS_ERR_MASK | \
		ADF_4XXX_TIMISCSTS_ERRTYPE_MASK)

#define ADF_4XXX_IASTATSSM_UERRSSMSH_MASK  BIT(0)
#define ADF_4XXX_IASTATSSM_CERRSSMSH_MASK  BIT(1)
#define ADF_4XXX_IASTATSSM_UERRSSMMMP0_MASK  BIT(2)
#define ADF_4XXX_IASTATSSM_CERRSSMMMP0_MASK  BIT(3)
#define ADF_4XXX_IASTATSSM_UERRSSMMMP1_MASK  BIT(4)
#define ADF_4XXX_IASTATSSM_CERRSSMMMP1_MASK  BIT(5)
#define ADF_4XXX_IASTATSSM_UERRSSMMMP2_MASK  BIT(6)
#define ADF_4XXX_IASTATSSM_CERRSSMMMP2_MASK  BIT(7)
#define ADF_4XXX_IASTATSSM_UERRSSMMMP3_MASK  BIT(8)
#define ADF_4XXX_IASTATSSM_CERRSSMMMP3_MASK  BIT(9)
#define ADF_4XXX_IASTATSSM_UERRSSMMMP4_MASK  BIT(10)
#define ADF_4XXX_IASTATSSM_CERRSSMMMP4_MASK  BIT(11)
#define ADF_4XXX_IASTATSSM_PPERR_MASK    BIT(12)
#define ADF_4XXX_IASTATSSM_SPPPAR_ERR_MASK  BIT(14)
#define ADF_4XXX_IASTATSSM_CPPPAR_ERR_MASK  BIT(15)
#define ADF_4XXX_IASTATSSM_RFPAR_ERR_MASK  BIT(16)

/* HI AE Correctable Error Log */
#define ADF_4XXX_HIAECORERRLOG_CPP0 (0x41A308)

/* HI AE Correctable Error Log Mask */
#define ADF_4XXX_HIAECORERRLOG_CPP0_MASK (0x1FF)

/* HI CPP Agents Command parity Error Log */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOG (0x41A310)

#define ADF_4XXX_PPERR_INTS_CLEAR_MASK BIT(0)

/* Resource manager error status */
#define ADF_4XXX_RSRCMGRERROR (0x448)

#define ADF_4XXX_SSMSOFTERRORPARITY(i) ((i) * 0x4000 + 0x1000)
#define ADF_4XXX_SSMCPPERR(i) ((i) * 0x4000 + 0x224)

#define ADF_4XXX_SER_ERR_SSMSH (0x44C)

/*  SPP pull cmd parity err_*slice* CSR  */
#define ADF_4XXX_SPPPULLCMDPARERR_ATH_CPH (0x1A4)
#define ADF_4XXX_SPPPULLCMDPARERR_CPR_XLT (0x1A8)
#define ADF_4XXX_SPPPULLCMDPARERR_WAT_WCP (0x1AC)
#define ADF_4XXX_SPPPULLCMDPARERR_DCPR_UCS (0x1B0)
#define ADF_4XXX_SPPPULLCMDPARERR_PKE (0x1B4)

/*  SPP pull data parity err_*slice* CSR  */
#define ADF_4XXX_SPPPULLDATAPARERR_ATH_CPH (0x1BC)
#define ADF_4XXX_SPPPULLDATAPARERR_CPR_XLT (0x1C0)
#define ADF_4XXX_SPPPULLDATAPARERR_WAT_WCP (0x1C4)
#define ADF_4XXX_SPPPULLDATAPARERR_DCPR_UCS (0x1C8)
#define ADF_4XXX_SPPPULLDATAPARERR_PKE (0x1CC)

/*  SPP push cmd parity err_*slice* CSR  */
#define ADF_4XXX_SPPPUSHCMDPARERR_ATH_CPH (0x1D4)
#define ADF_4XXX_SPPPUSHCMDPARERR_CPR_XLT (0x1D8)
#define ADF_4XXX_SPPPUSHCMDPARERR_WAT_WCP (0x1DC)
#define ADF_4XXX_SPPPUSHCMDPARERR_DCPR_UCS (0x1E0)
#define ADF_4XXX_SPPPUSHCMDPARERR_PKE (0x1E4)

/*  SPP push data parity err_*slice* CSR  */
#define ADF_4XXX_SPPPUSHDATAPARERR_ATH_CPH (0x1EC)
#define ADF_4XXX_SPPPUSHDATAPARERR_CPR_XLT (0x1F0)
#define ADF_4XXX_SPPPUSHDATAPARERR_WAT_WCP (0x1F4)
#define ADF_4XXX_SPPPUSHDATAPARERR_DCPR_UCS (0x1F8)
#define ADF_4XXX_SPPPUSHDATAPARERR_PKE (0x1FC)

/* Bitmasks for non-reserved bits for other parity error registers */
#define ADF_4XXX_SPP_PARERR_ATH_CPH_MASK (0xF000F)
#define ADF_4XXX_SPP_PARERR_CPR_XLT_MASK (0x10001)
#define ADF_4XXX_SPP_PARERR_DCPR_UCS_MASK (0x30007)
#define ADF_4XXX_SPP_PARERR_PKE_MASK (0x3F)

/* Misc interrupts and errors. */
#define ADF_4XXX_SINTPF (0x41A080)

/* RI CPP interface Status Register */
#define ADF_4XXX_RICPPINTSTS (0x41A330)

/* Mask of uncorrectable error flags in RICPPINTSTS register
 * BIT(0) RI asserted the CPP error signal during a push
 * BIT(1) RI detected the CPP error signal asserted during a pull
 * BIT(2) RI detected a push data parity error
 * BIT(3) RI detected a push valid parity error
 */
#define ADF_4XXX_RICPPINTSTS_MASK (BIT(0) | BIT(1) | BIT(2) | BIT(3))

/* RI Push ID of Uncorrectable Error Transaction Register */
#define ADF_4XXX_RIERRPUSHID (0x41A334)

/* RI Pull ID of Uncorrectable Error Transaction Register */
#define ADF_4XXX_RIERRPULLID (0x41A338)

/* Debug Parity Error RF enable per RF */
#define ADF_4XXX_REG_RF_PARITY_ERR_STS		(0x1728)

/* TI_PUSHFU Parity Reporting Disable. */
#define ADF_4XXX_TI_PUSHFUB_PAR_ERR_MASK (0x50062C)

/* TI_TRNSB Parity Reporting Disable. */
#define ADF_4XXX_TI_TRNSB_PAR_ERR_MASK (0x500644)

/* TI_CI Parity Reporting Disable register */
#define ADF_4XXX_TI_CI_PAR_ERR_MASK (0x500608)

/* TI_CD Parity Reporting Disable. */
#define ADF_4XXX_TI_CD_PAR_ERR_MASK (0x500638)

/* Parity Reporting Disable. */
#define ADF_4XXX_TI_PULL0FUB_PAR_ERR_MASK (0x500614)

/* RL Parity Reporting Disable. */
#define ADF_4XXX_RL_PAR_ERR_MASK (0x500650)

/* QM Parity Reporting Disable. */
#define ADF_4XXX_QM_PAR_ERR_MASK (0x50065C)

/* Debug Parity Error RF enable per RF */
#define ADF_4XXX_REG_RF_PARITY_ERR_EN		(0x172C)

/* Debug Parity Error RF interrupt enable */
#define ADF_4XXX_REG_RF_PARITY_ERR_INTEN	(0x1730)

/* Debug Parity Error RF mask */
#define ADF_4XXX_REG_RF_PARITY_ERR_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(4))

#define ADF_4XXX_REG_ME_TH_STATUS_NUM_ME_CLUSTER (2)

/* Log the error status of every ME thread */
#define ADF_4XXX_REG_ME_TH_STATUS(i) (0x173C + ((i) * 0x4))

/* Error status, one bit per thread. When a pull error is detected on a Pull
 * from ME the thread bit is set in this CSR.
 * Actual ME == (reg_me_th_status[num] * 4) + 2.
 */
#define ADF_4XXX_REG_ME_TH_STATUS_ME3_MASK	(0xFFu << 24)
#define ADF_4XXX_REG_ME_TH_STATUS_ME2_MASK	(0xFFu << 16)
#define ADF_4XXX_REG_ME_TH_STATUS_ME1_MASK	(0xFFu << 8)
#define ADF_4XXX_REG_ME_TH_STATUS_ME0_MASK	(0xFFu)

#define ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME0(i) ((i) * 4)
#define ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME1(i) (((i) * 4) + 1)
#define ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME2(i) (((i) * 4) + 2)
#define ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME3(i) (((i) * 4) + 3)

/* This CSR logs ATU detected fault. There is 1 CSR per Ring Pair. */
#define ADF_4XXX_ATUFAULTSTATUS(i)	(0x506000 + ((i) * 0x4))
#define ADF_4XXX_ATUFAULTSTATUS_NUM_RING_PAIR	(ADF_4XXX_ETR_MAX_BANKS)
/* ATU detects a fault */
#define ADF_4XXX_ATUFAULTSTATUS_INTFAULT_MASK	BIT(0)
/* Fault type detected by the ATU */
#define ADF_4XXX_ATUFAULTSTATUS_ERROR_TYPE_MASK	(0x7 << 1)

/* Parity status registers */
#define ADF_4XXX_AT_PAR_STS (0x50560C)
#define ADF_4XXX_AT_SC_PAR_STS (0x505618)
#define ADF_4XXX_AT_SRT_PAR_STS (0x505624)
#define ADF_4XXX_AT_PAYLOAD_PAR_STS (0x505630)
#define ADF_4XXX_AT_GLOBAL0_PAR_STS (0x50563C)
#define ADF_4XXX_AT_GLOBAL1_PAR_STS (0x505644)

#define ADF_4XXX_QM_PAR_STS (0x500660)
#define ADF_4XXX_RL_PAR_STS (0x500654)
#define ADF_4XXX_TI_MEM_PAR_ERR_FIRST_ERROR (0x500600)
#define ADF_4XXX_TI_PULL0FUB_PAR_STS (0x500618)
#define ADF_4XXX_TI_PUSHFUB_PAR_STS (0x500630)
#define ADF_4XXX_TI_CD_PAR_STS (0x50063C)
#define ADF_4XXX_TI_CI_PAR_STS (0x50060C)
#define ADF_4XXX_TI_TRNSB_PAR_STS (0x500648)
/* RI CPP interface control register. */
#define ADF_4XXX_RICPPINTCTL (0x41A32C)

/* AT exception status register */
#define ADF_4XXX_AT_EXCEP_STS (0x50502C)

/*
 * BIT(4) enables the stop feature of the stop and stream for all RI CPP
 * Command RFs.
 * BIT(3) enables checking parity on CPP.
 * BIT(2) enables error detection and reporting on the RI Parity Error.
 * BIT(1) enables error detection and reporting on the RI CPP Pull interface.
 * BIT(0) enables error detection and reporting on the RI CPP Push interface.
 */
#define ADF_4XXX_RICPP_EN (BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0))

/* CPP CFC Error PPID Register lower bits*/
#define ADF_4XXX_CPP_CFC_ERR_PPID_LO (0x640C0C)

/* CPP CFC Error PPID Register upper bits */
#define ADF_4XXX_CPP_CFC_ERR_PPID_HI (0x640C10)

/* TI Pull ID of Uncorrectable Error Transaction Register */
#define ADF_4XXX_TIERRPULLID (0x500544)

/* TI Push ID of Uncorrectable Error Transaction Register */
#define ADF_4XXX_TIERRPUSHID (0x500540)

/* TI Push Pull ID of Error Transaction Register */
#define ADF_4XXX_TIERRPPID (0x500550)

/* TI CPP interface Status Register */
#define ADF_4XXX_TICPPINTSTS (0x50053C)

/* Mask of Uncorrectable error flags in TICPPINTSTS register
 * BIT(0) TI asserted the CPP error signal during a push
 * BIT(1) TI detected the CPP error signal asserted during a pull
 * BIT(2) TI detected a pull data parity error
 */
#define ADF_4XXX_TICPPINTSTS_MASK (BIT(0) | BIT(1) | BIT(2))

/* TI CPP interface Error Control Register */
#define ADF_4XXX_TICPPINTCTL (0x500538)

/* Rate Limiter Error Log Register */
#define ADF_4XXX_RLT_ERRLOG (0x508814)

/*
 * BIT(4) enables TI stop part of stop and scream mode on CPP/RF Parity errors.
 * BIT(3) enables errenpar for Pull Data logging.
 * BIT(2) enables parity error detection and logging on the TI CPP Pull
 * interface.
 * BIT(1) enables error detection and reporting on the TI CPP Pull interface.
 * BIT(0) enables error detection and reporting on the TI CPP Push interface.
 */
#define ADF_4XXX_TICPP_EN (BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0))

/* Rate Limiter Error Log status */
#define ADF_4XXX_RLT_ERRLOG_STATUS_MASK		(0xF)

/* CPP error control and logging register */
#define ADF_4XXX_CPP_CFC_ERR_CTRL (0x640C00)

/* CPP CFC error status register. */
#define ADF_4XXX_CPP_CFC_ERR_STATUS (0x640C04)

/*
 * BIT(1) enables generation of irqs to the PCIe endpoint
 *        for the errors specified in CPP_CFC_ERR_STATUS
 * BIT(0) enables detecting and logging of push/pull data errors.
 */
#define ADF_4XXX_CPP_CFC_UE (BIT(1) | BIT(0))

#define ARAM_CSR_BAR_OFFSET  0

/* ARAM error interrupt enable registers */
#define ADF_4XXX_ARAMCERR (ARAM_CSR_BAR_OFFSET + 0x1700)
#define ADF_4XXX_ARAMUERR (ARAM_CSR_BAR_OFFSET + 0x1704)

/* ARAM Correctable errors defined in ARAMCERR
 * BIT(0) Indicates a CERR is reported
 * BIT(3) Enable bit to fix and log Correctable errors
 * BIT(26) Enable Correctable errors bit
 */
#define ADF_4XXX_ARAM_CERR_MASK	(BIT(0))
#define ADF_4XXX_ARAM_CERR (BIT(3) | BIT(26))

/* ARAM Uncorrectable errors defined in ARAMUERR
 * BIT(0)  Indicates Legacy Uncorrectable Error
 * BIT(3)  Enable ARAM RAM to detect and log legacy Unorrectable errors
 * BIT(18) Indicates that multiple legacy Uncorrectable Errors have occurred
 * BIT(19) Enable ECC Uncorrectable or Parity errors
 */
#define ADF_4XXX_ARAM_UERR_EN (BIT(3) | BIT(19))

/* Legacy Uncorrectable Error */
#define ADF_4XXX_REG_ARAMUERR_UERR_MASK	BIT(0)
/* Multiple Legacy Uncorrectable Error */
#define ADF_4XXX_REG_ARAMUERR_MERR_MASK	BIT(18)
/* ARAM register UE error mask */
#define ADF_4XXX_ARAMUERR_MASK ( \
		(ADF_4XXX_REG_ARAMUERR_UERR_MASK) | \
		(ADF_4XXX_REG_ARAMUERR_MERR_MASK))

#define ADF_4XXX_CPPMEMTGTERR (ARAM_CSR_BAR_OFFSET + 0x1710)

/* Misc memory target errors registers mask
 * BIT(0) One or more errors occurred
 * BIT(1) Multiple errors
 * BIT(2) Push/Pull error enable
 * BIT(4) Pull error
 * BIT(5) Parity pull error
 * BIT(6) Push error
 * BIT(7) Pull/Push errors will generate an Interrupt to RI
 * BIT(8) ARAM will check parity on the pull data bus and the CPP command bus
 * BIT(9) ARAM will autopush to ME when a Push/Parity error on
 *	  lookaside DT is detected
 */
#define ADF_4XXX_REG_CPPMEMTGTERR_UE_MASK \
	(BIT(0) | BIT(1) | BIT(4) | BIT(5) | BIT(6))

#define ADF_4XXX_REG_CPPMEMTGTERR_EN_MASK \
	(BIT(2) | BIT(7) | BIT(8) | BIT(9))

/* Correctable/Uncorrectable ECC Block Enable Error in ARAM */
#define ADF_4XXX_REG_ARAMCERRUERR_EN (0x1808)

/* Correctable/Uncorrectable ECC Block Enable Error in ARAM bitmask
 * BIT(0) ARAM CD's ECC Check Block Enabled
 * BIT(1) ARAM PULL REQ's ECC Check Block Enabled
 * BIT(2) ARAM CMD_DISPATCH's ECC Check Block Enabled
 * BIT(3) ARAM RD_DPTH's Push Data ECC Check Block Enabled
 * BIT(4) ARAM RD_DPTH's Read Data ECC Check Block Enabled
 * BIT(5) ARAM RMW's ECC Check Block Enabled
 * BIT(6) ARAM WR DPTH's RMW ECC Check Block Enabled
 * BIT(7) ARAM WR DPTH Write Data ECC Check Block Enabled
 */
#define ADF_4XXX_REG_ARAMCERRUERR_EN_UCERR_MASK \
	(BIT(0) | BIT(1) | BIT(2) | BIT(3) | \
	 BIT(4) | BIT(5) | BIT(6) | BIT(7))

/* Error registers for MMP. */
#define ADF_4XXX_MAX_MMP (5)

#define ADF_4XXX_MMP_BASE(i)       ((i) * 0x1000 % 0x3800)
#define ADF_4XXX_CERRSSMMMP(i, n)  ((i) * 0x4000 + \
		     ADF_4XXX_MMP_BASE(n) + 0x380)
#define ADF_4XXX_UERRSSMMMP(i, n)  ((i) * 0x4000 + \
		     ADF_4XXX_MMP_BASE(n) + 0x388)
#define ADF_4XXX_UERRSSMMMPAD(i, n)    ((i) * 0x4000 + \
		     ADF_4XXX_MMP_BASE(n) + 0x38C)
#define ADF_4XXX_INTMASKSSM(i)     ((i) * 0x4000 + 0x0)

#define ADF_4XXX_UERRSSMMMP_INTS_CLEAR_MASK ((BIT(16) || BIT(0)))
#define ADF_4XXX_CERRSSMMMP_INTS_CLEAR_MASK BIT(0)

/* HI ME Uncorrectable Error Log mask */
/* TI command parity error */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOG_TICMDPARERR	BIT(0)
/* RI command parity error */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOG_RICMDPARERR	BIT(1)
/* ARAM command parity error */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOG_ARAMCMDPARERR	BIT(2)
/* CFC command parity error */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOG_CFCCMDPARERR	BIT(3)
/* SSM[0:1] command parity error */
#define ADF_4XXX_HICPPAGENTCMDPARERRLOG_SSMCMDPARERR	BIT(4)

#define ADF_4XXX_HICPPAGENTCMDPARERRLOG_UC_ERR_MASK ( \
	(ADF_4XXX_HICPPAGENTCMDPARERRLOG_TICMDPARERR) | \
	(ADF_4XXX_HICPPAGENTCMDPARERRLOG_RICMDPARERR) | \
	(ADF_4XXX_HICPPAGENTCMDPARERRLOG_ARAMCMDPARERR) | \
	(ADF_4XXX_HICPPAGENTCMDPARERRLOG_CFCCMDPARERR) | \
	(ADF_4XXX_HICPPAGENTCMDPARERRLOG_SSMCMDPARERR))

/* Status Register to log misc error on RI */
#define ADF_4XXX_RIMISCSTS (0x41B1B8)

/* Command Parity error detected on IOSFP Command to QAT */
#define ADF_4XXX_RIMISCSTS_UC_ERR_MASK BIT(0)

/* ARAM region sizes in bytes */
#define ADF_4XXX_DEF_ASYM_MASK 0x1

/* Arbiter configuration */
#define ADF_4XXX_ARB_OFFSET			(0x0)
#define ADF_4XXX_ARB_WRK_2_SER_MAP_OFFSET      (0x400)

/* Admin Interface Reg Offset */
#define ADF_4XXX_ADMINMSGUR_OFFSET         (0x500574)
#define ADF_4XXX_ADMINMSGLR_OFFSET         (0x500578)
#define ADF_4XXX_MAILBOX_BASE_OFFSET       (0x600970)

/*RP PASID register*/
#define ADF_4XXX_PASID_BASE (0x104000)

#define ADF_4XXX_PRIV_ENABLE_PIDVECTABLE BIT(31)
#define ADF_4XXX_PASID_ENABLE_PIDVECTABLE BIT(30)
#define ADF_4XXX_AT_ENABLE_PIDVECTABLE BIT(29)
#define ADF_4XXX_AI_ENABLE_PIDVECTABLE BIT(28)
#define ADF_4XXX_PRIV_ENABLE_PLD BIT(27)
#define ADF_4XXX_PASID_ENABLE_PLD BIT(26)
#define ADF_4XXX_AT_ENABLE_PLD BIT(25)
#define ADF_4XXX_AI_ENABLE_PLD BIT(24)
#define ADF_4XXX_PRIV_ENABLE_RING BIT(23)
#define ADF_4XXX_PASID_ENABLE_RING BIT(22)
#define ADF_4XXX_AT_ENABLE_RING BIT(21)
#define ADF_4XXX_AI_ENABLE_RING BIT(20)
#define ADF_4XXX_PASID_MSK (0xFFFFF)

/*User Queue*/
#define ADF_4XXX_UQPIDVECTABLELBASE (0x105000)
#define ADF_4XXX_UQPIDVECTABLEUBASE (0x105004)
#define ADF_4XXX_UQPIDVECTABLESIZE (0x105008)

#define ADF_4XXX_UQSWQWTRMRK (0x101044)

/*Reset*/

/*KPT reset*/
#define ADF_4XXX_KPTRP_RESETSTATUS0 (0x500A00)
#define ADF_4XXX_KPTRP_RESETSTATUS1 (0x500A04)

/*Ring Pair reset*/
#define ADF_4XXX_RPRESETCTL (0x106000)

/*qat_4xxx fuse bits are different from old GENs, redefine it*/
enum icp_qat_4xxx_slice_mask {
	ICP_ACCEL_4XXX_MASK_CIPHER_SLICE = 0x01,
	ICP_ACCEL_4XXX_MASK_AUTH_SLICE = 0x02,
	ICP_ACCEL_4XXX_MASK_PKE_SLICE = 0x04,
	ICP_ACCEL_4XXX_MASK_COMPRESS_SLICE = 0x08,
	ICP_ACCEL_4XXX_MASK_UCS_SLICE = 0x10,
	ICP_ACCEL_4XXX_MASK_EIA3_SLICE = 0x20,
	/*SM3&SM4 are indicated by same bit*/
	ICP_ACCEL_4XXX_MASK_SMX_SLICE = 0x80,
};

/* RL constants */
#define ADF_4XXX_RL_SLICE_REF 1000UL
#define ADF_4XXX_RL_MAX_TP_ASYM 173750UL
#define ADF_4XXX_RL_MAX_TP_SYM 95000UL
#define ADF_4XXX_RL_MAX_TP_DC 45000UL
#define ADF_401XX_RL_SLICE_REF 1000UL
#define ADF_401XX_RL_MAX_TP_ASYM 173750UL
#define ADF_401XX_RL_MAX_TP_SYM 95000UL
#define ADF_401XX_RL_MAX_TP_DC 45000UL

/* Interrupt Coalesce Timer Defaults */
#define ADF_4XXX_ACCEL_DEF_COALESCE_TIMER 1000
#define ADF_4XXX_COALESCING_MIN_TIME 0x1F
#define ADF_4XXX_COALESCING_MAX_TIME 0xFFFF
#define ADF_4XXX_COALESCING_DEF_TIME 0x1F4

/* Firmware Binary */
#define ADF_4XXX_FW "qat_4xxx.bin"
#define ADF_4XXX_MMP "qat_4xxx_mmp.bin"
#define ADF_4XXX_DC_OBJ "qat_4xxx_dc.bin"
#define ADF_4XXX_SYM_OBJ "qat_4xxx_sym.bin"
#define ADF_4XXX_ASYM_OBJ "qat_4xxx_asym.bin"
#define ADF_4XXX_ADMIN_OBJ "qat_4xxx_admin.bin"
#define ADF_402XX_FW "qat_402xx.bin"
#define ADF_402XX_MMP "qat_402xx_mmp.bin"
#define ADF_402XX_DC_OBJ "qat_402xx_dc.bin"
#define ADF_402XX_SYM_OBJ "qat_402xx_sym.bin"
#define ADF_402XX_ASYM_OBJ "qat_402xx_asym.bin"
#define ADF_402XX_ADMIN_OBJ "qat_402xx_admin.bin"

/*Only 3 types of images can be loaded including the admin image*/
#define ADF_4XXX_MAX_OBJ 3

void adf_init_hw_data_4xxx(struct adf_hw_device_data *hw_data, u32 id);
void adf_clean_hw_data_4xxx(struct adf_hw_device_data *hw_data);

int adf_4xxx_qat_crypto_dev_config(struct adf_accel_dev *accel_dev);

void adf_4xxx_handle_slice_hang_error(struct adf_accel_dev *accel_dev,
				      u32 accel_num,
				      void __iomem *csr);


#define ADF_4XXX_AE_FREQ          (1000 * 1000000)
#define ADF_4XXX_KPT_COUNTER_FREQ (100 * 1000000)
#endif
