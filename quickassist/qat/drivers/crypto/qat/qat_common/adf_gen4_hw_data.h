/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 Intel Corporation */
#ifndef ADF_GEN4_HW_DATA_H_
#define ADF_GEN4_HW_DATA_H_

#include "adf_accel_devices.h"

/* Error source registers */
#define ADF_GEN4_ERRSOU0	(0x41A200)
#define ADF_GEN4_ERRSOU1	(0x41A204)
#define ADF_GEN4_ERRSOU2	(0x41A208)
#define ADF_GEN4_ERRSOU3	(0x41A20C)

/* Error source mask registers */
#define ADF_GEN4_ERRMSK0	(0x41A210)
#define ADF_GEN4_ERRMSK1	(0x41A214)
#define ADF_GEN4_ERRMSK2	(0x41A218)
#define ADF_GEN4_ERRMSK3	(0x41A21C)

#define ADF_GEN4_VFLRNOTIFY	BIT(7)

/* Slice Hang enabling related registers  */
#define ADF_GEN4_SSMWDTL_OFFSET(i) (0x54 + ((i) * 0x800))
#define ADF_GEN4_SSMWDTH_OFFSET(i) (0x5C + ((i) * 0x800))
#define ADF_GEN4_SSMWDTPKEL_OFFSET(i) (0x58 + ((i) * 0x800))
#define ADF_GEN4_SSMWDTPKEH_OFFSET(i) (0x60 + ((i) * 0x800))

#define ADF_GEN4_SSM_WDT_64BIT_DEFAULT_VALUE (0x500000000ULL)

/* PCIe configuration space */
#define ADF_GEN4_SRAM_BAR 0
#define ADF_GEN4_PMISC_BAR 1
#define ADF_GEN4_ETR_BAR 2
#define ADF_GEN4_UQ_BAR 2
#define ADF_GEN4_ETR_MAX_BANKS 64
/*
 * Power management interrupt mask
 * in ERRSOU2 and ERRMSK2
 */
#define ADF_GEN4_PM_INTERRUPT_MASK BIT(18)

/* Number of heartbeat counter pairs */
#define ADF_NUM_HB_CNT_PER_AE (ADF_NUM_THREADS_PER_AE)

/* Clock Gating Control IOSF Primary Register */
#define ADF_GEN4_PFCGC_IOSF_PRIR	(0x2C0)

/* BIT(16) Parity Check Enable */
#define ADF_GEN4_PFCGC_IOSF_PRIR_MASK	(BIT(16))

/* UQ Base */
#define ADF_GEN4_UQ_BASE         0x180000

int adf_init_chaining(struct adf_accel_dev *accel_dev);
int adf_gen4_send_admin_init(struct adf_accel_dev *accel_dev);
int adf_gen4_get_uq_base_addr(struct adf_accel_dev *accel_dev,
			      void **uq_base_addr,
			      u32 bank_number);
int adf_gen4_ring_pair_reset(struct adf_accel_dev *accel_dev,
			     u32 bank_number);
int adf_gen4_ring_pair_drain(struct adf_accel_dev *accel_dev,
			     u32 bank_number, int timeout_ms);
void adf_gen4_config_ring_irq(struct adf_accel_dev *accel_dev,
			      u32 bank_number, u16 ring_mask);
int adf_gen4_qat_crypto_dev_config(struct adf_accel_dev *accel_dev);
int adf_gen4_set_ssm_wdtimer(struct adf_accel_dev *accel_dev);
void adf_gen4_set_msix_default_rttable(struct adf_accel_dev *accel_dev);
uint32_t get_obj_cfg_ae_mask(struct adf_accel_dev *accel_dev,
			     enum adf_accel_unit_services service);
enum adf_accel_unit_services
	adf_gen4_get_service_type(struct adf_accel_dev *accel_dev, s32 obj_num);
int adf_gen4_check_svc_to_hw_capabilities(struct adf_accel_dev *accel_dev,
					  u32 required_capability);
void adf_gen4_cfg_get_accel_algo_cap(struct adf_accel_dev *accel_dev);

#endif /* ADF_GEN4_HW_DATA_H_ */
