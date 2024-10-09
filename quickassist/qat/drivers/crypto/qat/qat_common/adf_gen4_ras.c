// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2022 Intel Corporation */

#include "adf_accel_devices.h"
#include "adf_gen4_ras.h"

static void adf_poll_csr(struct adf_accel_dev *accel_dev,
			 void __iomem *csr, u32 slice_hang_offset,
			 u32 max_retry, char *slice_name)
{
	u32 slice_hang_reg;
	u32 num_retry = 0;

	do {
		slice_hang_reg = ADF_CSR_RD(csr, slice_hang_offset);
		num_retry += 1;
	} while (slice_hang_reg && max_retry > num_retry);

	if (slice_hang_reg)
		dev_err(&GET_DEV(accel_dev),
			"FW can't recover from slice %s hang: %x\n",
			slice_name, slice_hang_reg);
}

void adf_gen4_handle_slice_hang_error(struct adf_accel_dev *accel_dev,
				      u32 accel_num, void __iomem *csr)
{
	u32 stat_ath_cph_offset;
	u32 stat_cpr_xlt_offset;
	u32 stat_dcpr_ucs_offset;
	u32 stat_pke_offset;
	u32 max_retry = 5;

	stat_ath_cph_offset =
		ADF_GEN4_SLICEHANGSTATUS_ATH_CPH_OFFSET(accel_num);
	stat_cpr_xlt_offset =
		ADF_GEN4_SLICEHANGSTATUS_CPR_XLT_OFFSET(accel_num);
	stat_dcpr_ucs_offset =
		ADF_GEN4_SLICEHANGSTATUS_DCPR_UCS_OFFSET(accel_num);
	stat_pke_offset =
		ADF_GEN4_SLICEHANGSTATUS_PKE_OFFSET(accel_num);

	adf_poll_csr(accel_dev, csr,
		     stat_ath_cph_offset, max_retry, "ath_cph");
	adf_poll_csr(accel_dev, csr,
		     stat_cpr_xlt_offset, max_retry, "cpr_xlt");
	adf_poll_csr(accel_dev, csr,
		     stat_dcpr_ucs_offset, max_retry, "dcpr_ucs");
	adf_poll_csr(accel_dev, csr, stat_pke_offset, max_retry, "pke");

	/*
	 * IA clears BIT(3) of IAINTSTATSSM
	 * Increase Correctable error counter
	 */
	adf_csr_fetch_and_or(csr,
			     ADF_GEN4_IAINTSTATSSM(accel_num),
			     ADF_GEN4_SLICE_HANG_ERROR_MASK);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);
}
EXPORT_SYMBOL_GPL(adf_gen4_handle_slice_hang_error);
