// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2018, 2021 Intel Corporation */

#include <linux/sysfs.h>
#include <linux/pci.h>
#include <linux/bitops.h>
#include <linux/atomic.h>
#include <linux/string.h>

#include "adf_accel_devices.h"
#include "adf_4xxx_hw_data.h"
#include "adf_4xxx_ras.h"

#include <adf_dev_err.h>

static ssize_t
adf_ras_show(struct device *dev, struct device_attribute *dev_attr, char *buf)
{
	struct adf_accel_dev *accel_dev = pci_get_drvdata(to_pci_dev(dev));
	struct attribute *attr = &dev_attr->attr;
	unsigned long counter;

	if (!strcmp(attr->name, "ras_correctable")) {
		counter = atomic_read(&accel_dev->ras_counters[ADF_RAS_CORR]);
	} else if (!strcmp(attr->name, "ras_uncorrectable")) {
		counter = atomic_read(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	} else if (!strcmp(attr->name, "ras_fatal")) {
		counter = atomic_read(&accel_dev->ras_counters[ADF_RAS_FATAL]);
	} else {
		dev_err(&GET_DEV(accel_dev), "Unknown attribute %s\n",
			attr->name);
		return -EFAULT;
	}

	return scnprintf(buf, PAGE_SIZE, "%ld\n", counter);
}

DEVICE_ATTR(ras_correctable, S_IRUSR|S_IRGRP|S_IROTH, adf_ras_show, NULL);
DEVICE_ATTR(ras_uncorrectable, S_IRUSR|S_IRGRP|S_IROTH, adf_ras_show, NULL);
DEVICE_ATTR(ras_fatal, S_IRUSR|S_IRGRP|S_IROTH, adf_ras_show, NULL);

static ssize_t
adf_ras_store(struct device *dev, struct device_attribute *dev_attr,
	      const char *buf, size_t count)
{
	struct adf_accel_dev *accel_dev = pci_get_drvdata(to_pci_dev(dev));
	struct attribute *attr = &dev_attr->attr;

	if (!strcmp(attr->name, "ras_reset")) {
		if (buf[0] != '0' || count != 2)
			return -EINVAL;

		atomic_set(&accel_dev->ras_counters[ADF_RAS_CORR], 0);
		atomic_set(&accel_dev->ras_counters[ADF_RAS_UNCORR], 0);
		atomic_set(&accel_dev->ras_counters[ADF_RAS_FATAL], 0);
	} else {
		dev_err(&GET_DEV(accel_dev), "Unknown attribute %s\n",
			attr->name);
		return -EFAULT;
	}

	return count;
}

DEVICE_ATTR(ras_reset, S_IWUSR, NULL, adf_ras_store);

static void enable_reporting_to_errsoux(void __iomem *csr)
{
	/* Enable correctable errors reporting in ERRSOU0 */
	adf_csr_fetch_and_and(csr, ADF_4XXX_ERRMSK0, ~ADF_4XXX_ERRMSK0_CERR);

	/* Enable uncorrectable errors reporting in ERRSOU1 */
	adf_csr_fetch_and_and(csr, ADF_4XXX_ERRMSK1, ~ADF_4XXX_ERRMSK1_UERR);

	/* Enable uncorrectable errors reporting in ERRSOU2 */
	adf_csr_fetch_and_and(csr, ADF_4XXX_ERRMSK2, ~ADF_4XXX_ERRMSK2_UERR);

	/* Enable uncorrectable/correctable errors reporting in ERRSOU3 */
	adf_csr_fetch_and_and(csr, ADF_4XXX_ERRMSK3, ~(ADF_4XXX_ERRMSK3_UERR |
						       ADF_4XXX_ERRMSK3_CERR));
}

static void enable_aram_errors_reporting(void __iomem *csr)
{
	/* Enable detection of Uncorrectable ECC Block Error in ARAM */
	adf_csr_fetch_and_or(csr, ADF_4XXX_REG_ARAMCERRUERR_EN,
			     ADF_4XXX_REG_ARAMCERRUERR_EN_UCERR_MASK);

	/* Enable detection of Uncorrectable Errors in ARAM register */
	adf_csr_fetch_and_or(csr, ADF_4XXX_ARAMUERR,
			     ADF_4XXX_ARAM_UERR_EN);

	/* Enable Correctable Error detection in ARAM register */
	adf_csr_fetch_and_or(csr, ADF_4XXX_ARAMCERR,
			     ADF_4XXX_ARAM_CERR);

	/* Enable misc memory target error registers */
	adf_csr_fetch_and_or(csr, ADF_4XXX_CPPMEMTGTERR,
			     ADF_4XXX_REG_CPPMEMTGTERR_EN_MASK);
}

static void enable_rf_errors_reporting(void __iomem *csr)
{
	/* Enable Debug Parity Error per RF */
	adf_csr_fetch_and_or(csr, ADF_4XXX_REG_RF_PARITY_ERR_EN,
			     ADF_4XXX_REG_RF_PARITY_ERR_MASK);

	/* Enable Debug Parity Error RF interrupt */
	adf_csr_fetch_and_or(csr, ADF_4XXX_REG_RF_PARITY_ERR_INTEN,
			     ADF_4XXX_REG_RF_PARITY_ERR_MASK);

        /* Enable RF Parity Error reporting in Shared RAM */
	adf_csr_fetch_and_or(csr, ADF_4XXX_SSMSOFTERRORPARITYMASK_SRC,
			     ADF_4XXX_SSMSOFTERRORPARITY_SRC_MASK);

	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SSMSOFTERRORPARITYMASK_ATH_CPH,
			      ~ADF_4XXX_SPPPARERRMSK_ATH_CPH_MASK);

	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SSMSOFTERRORPARITYMASK_CPR_XLT,
			      ~ADF_4XXX_SPPPARERRMSK_CPR_XLT_MASK);

	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SSMSOFTERRORPARITYMASK_DCPR_UCS,
			      ~ADF_4XXX_SPPPARERRMSK_DCPR_UCS_MASK);

	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SSMSOFTERRORPARITYMASK_PKE,
			      ~ADF_4XXX_SPPPARERRMSK_PKE_MASK);
}

static void enable_ae_errors_reporting(void __iomem *csr,
				       const unsigned long ae_mask)
{
	u32 bit_iterator;

	/* Enable Acceleration Engine Uncorrectable Errors */
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_HIAEUNCERRLOGENABLE_CPP0,
			     ADF_4XXX_HIAEUNCERRLOGENABLE_CPP0_MASK);

	/* Enable Acceleration Engine Correctable Errors */
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_HIAECORERRLOGENABLE_CPP0,
			     ADF_4XXX_HIAECORERRLOGENABLE_CPP0_MASK);

	/* Enable Acceleration Engine error detection & correction */
	for_each_set_bit(bit_iterator, &ae_mask, ADF_4XXX_MAX_ACCELENGINES) {
		adf_csr_fetch_and_or(csr,
				     ADF_4XXX_AE_CTX_ENABLES(bit_iterator),
				     ADF_4XXX_ENABLE_AE_ECC_ERR);
	}
}

static void enable_ssm_errors_reporting(void __iomem *csr,
					const unsigned long accel_mask)
{
	u32 bit_iterator;

	for_each_set_bit(bit_iterator, &accel_mask, ADF_4XXX_MAX_ACCELERATORS) {
		/* Enable shared memory error detection & correction */
		adf_csr_fetch_and_or(csr, ADF_4XXX_SSMFEATREN(bit_iterator),
				     (ADF_4XXX_SSMFEATREN_UE_MASK |
				      ADF_4XXX_SSMFEATREN_CE_MASK));

		/* Enable SSM interrupts - ECC, CPP and SER */
		adf_csr_fetch_and_or(csr, ADF_4XXX_INTMASKSSM(bit_iterator),
				     (ADF_4XXX_INTMASKSSM_UE |
				      ADF_4XXX_INTMASKSSM_CERR));
	}

	/* Enable SER detection in SER_err_ssmsh register according to RAS
	 * compliance
	 */
	adf_csr_fetch_and_or(csr, ADF_4XXX_SER_EN_SSMSH,
			     (ADF_4XXX_SER_EN_SSMSH_UCERR_MASK |
			      ADF_4XXX_SER_EN_SSMSH_CERR_MASK));

	/* Enable SSM soft Parity Errors */
	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SPPPARERRMSK_ATH_CPH,
			      ~ADF_4XXX_SPPPARERRMSK_ATH_CPH_MASK);
	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SPPPARERRMSK_CPR_XLT,
			      ~ADF_4XXX_SPPPARERRMSK_CPR_XLT_MASK);
	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SPPPARERRMSK_DCPR_UCS,
			      ~ADF_4XXX_SPPPARERRMSK_DCPR_UCS_MASK);
	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_SPPPARERRMSK_PKE,
			      ~ADF_4XXX_SPPPARERRMSK_PKE_MASK);

	for_each_set_bit(bit_iterator, &accel_mask, ADF_4XXX_MAX_ACCELERATORS) {
		/* Unmask Slice Hang interrupts so they can be seen by IA. */
		adf_csr_fetch_and_and(csr,
				      ADF_4XXX_SHINTMASKSSM_ATH_CPH_OFFSET(bit_iterator),
				      ~ADF_4XXX_SHINTMASKSSM_ATH_CPH_MASK);
		adf_csr_fetch_and_and(csr,
				      ADF_4XXX_SHINTMASKSSM_CPR_XLT_OFFSET(bit_iterator),
				      ~ADF_4XXX_SHINTMASKSSM_CPR_XLT_MASK);
		adf_csr_fetch_and_and(csr,
				      ADF_4XXX_SHINTMASKSSM_DCPR_UCS_OFFSET(bit_iterator),
				      ~ADF_4XXX_SHINTMASKSSM_DCPR_UCS_MASK);
		adf_csr_fetch_and_and(csr,
				      ADF_4XXX_SHINTMASKSSM_PKE_OFFSET(bit_iterator),
				      ~ADF_4XXX_SHINTMASKSSM_PKE_MASK);
	}
}

static void enable_ti_ri_errors_reporting(void __iomem *csr)
{
	/* Enable error detection and reporting in TIMISCSTS */
	adf_csr_fetch_and_or(csr, ADF_4XXX_TIMISCCTL,
			     ADF_4XXX_TIMISCCTL_ERREN_MASK);

	/* Enable error handling in RI, TI CPP interface control registers */
	adf_csr_fetch_and_or(csr, ADF_4XXX_RICPPINTCTL, ADF_4XXX_RICPP_EN);
	adf_csr_fetch_and_or(csr, ADF_4XXX_TICPPINTCTL, ADF_4XXX_TICPP_EN);

	/* Enable RI Internal Memory & RF Parity Error */
	adf_csr_fetch_and_or(csr, ADF_4XXX_RI_MEM_PAR_ERR_EN0,
			     ADF_4XXX_RI_MEM_PAR_ERR_EN0_UC_MASK);

	/* Enable TI Internal Memory Parity Error reporting */
	adf_csr_fetch_and_and(csr, ADF_4XXX_TI_CI_PAR_ERR_MASK,
			      ~ADF_4XXX_TI_CI_PAR_ERR_RW_BITMASK);
	adf_csr_fetch_and_and(csr, ADF_4XXX_TI_PULL0FUB_PAR_ERR_MASK,
			      ~ADF_4XXX_TI_PULL0FUB_PAR_ERR_RW_BITMASK);
	adf_csr_fetch_and_and(csr, ADF_4XXX_TI_PUSHFUB_PAR_ERR_MASK,
			      ~ADF_4XXX_TI_PUSHFUB_PAR_ERR_RW_BITMASK);
	adf_csr_fetch_and_and(csr, ADF_4XXX_TI_CD_PAR_ERR_MASK,
			      ~ADF_4XXX_TI_CD_PAR_ERR_BITMASK);
	adf_csr_fetch_and_and(csr, ADF_4XXX_TI_TRNSB_PAR_ERR_MASK,
			      ~ADF_4XXX_TI_TRNSB_PAR_ERR_BITMASK);

	/* Enable RL Internal Memory Parity Error reporting */
	adf_csr_fetch_and_and(csr, ADF_4XXX_RL_PAR_ERR_MASK,
			      ~ADF_4XXX_RL_PAR_ERR_BITMASK);

	/* Enable QM Internal Memory Parity Error reporting */
	adf_csr_fetch_and_and(csr, ADF_4XXX_QM_PAR_ERR_MASK,
			      ~ADF_4XXX_QM_PAR_ERR_BITMASK);
}

static void enable_cpp_errors_reporting(void __iomem *csr)
{
	/* Enable CPP CFC Uncorrectable Errors */
	ADF_CSR_WR(csr, ADF_4XXX_CPP_CFC_ERR_CTRL,
		   ADF_4XXX_CPP_CFC_UE);
}

static void enable_misc_errors_reporting(void __iomem *csr)
{
	/* Enable IOSF Primary Command Parity error Reporting */
	adf_csr_fetch_and_or(csr, ADF_4XXX_RIMISCCTL,
			     ADF_4XXX_RIMISCCTL_MASK);

	/* Enable HI CPP Agents Command Parity Error Reporting */
	adf_csr_fetch_and_or(csr, ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE,
			     ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_MASK);
}

static void adf_4xxx_enable_ras(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	const unsigned long accel_mask = hw_data->accel_mask;
	const unsigned long ae_mask = hw_data->ae_mask;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)];
	void __iomem *csr = misc_bar->virt_addr;

	enable_reporting_to_errsoux(csr);
	enable_aram_errors_reporting(csr);
	enable_rf_errors_reporting(csr);
	enable_ae_errors_reporting(csr, ae_mask);
	enable_ssm_errors_reporting(csr, accel_mask);
	enable_ti_ri_errors_reporting(csr);
	enable_cpp_errors_reporting(csr);
	enable_misc_errors_reporting(csr);
}

int adf_4xxx_init_ras(struct adf_accel_dev *accel_dev)
{
	int i;

	accel_dev->ras_counters = kcalloc(ADF_RAS_ERRORS,
					  sizeof(*(accel_dev->ras_counters)),
					  GFP_KERNEL);
	if (!accel_dev->ras_counters)
		return -ENOMEM;

	for (i = 0; i < ADF_RAS_ERRORS; ++i)
		atomic_set(&accel_dev->ras_counters[i], 0);
	pci_set_drvdata(accel_to_pci_dev(accel_dev), accel_dev);
	device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_correctable);
	device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_uncorrectable);
	device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_fatal);
	device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_reset);

	adf_4xxx_enable_ras(accel_dev);

	return 0;
}

static void disable_reporting_to_errsoux(void __iomem *csr)
{
	/* Disable correctable errors in ERRSOU0 */
	adf_csr_fetch_and_or(csr, ADF_4XXX_ERRMSK0, ADF_4XXX_ERRMSK0_CERR);

	/* Disable uncorrectable errors in ERRSOU1 */
	adf_csr_fetch_and_or(csr, ADF_4XXX_ERRMSK1, ADF_4XXX_ERRMSK1_UERR);

	/* Disable uncorrectable errors in ERRSOU2 */
	adf_csr_fetch_and_or(csr, ADF_4XXX_ERRMSK2, ADF_4XXX_ERRMSK2_UERR);

	/* Disable uncorrectable/correctable errors in ERRSOU3 */
	adf_csr_fetch_and_or(csr, ADF_4XXX_ERRMSK3, ADF_4XXX_ERRMSK3_UERR |
						    ADF_4XXX_ERRMSK3_CERR);
}

static void disable_aram_errors_reporting(void __iomem *csr)
{
	/* Disable detection of Uncorrectable ECC Block Errors in ARAM */
	adf_csr_fetch_and_and(csr, ADF_4XXX_REG_ARAMCERRUERR_EN,
			      ~ADF_4XXX_REG_ARAMCERRUERR_EN_UCERR_MASK);

	/* Disable detection of Uncorrectable Errors in ARAM register */
	adf_csr_fetch_and_and(csr, ADF_4XXX_ARAMUERR,
			      ~ADF_4XXX_ARAM_UERR_EN);

	/* Disable Correctable Error detection in ARAM register */
	adf_csr_fetch_and_and(csr, ADF_4XXX_ARAMCERR,
			      ~ADF_4XXX_ARAM_CERR);

	/* Disable misc memory target error registers */
	adf_csr_fetch_and_and(csr, ADF_4XXX_CPPMEMTGTERR,
			      ~ADF_4XXX_REG_CPPMEMTGTERR_EN_MASK);
}

static void disable_rf_errors_reporting(void __iomem *csr)
{
	/* Disable Debug Parity Error per RF */
	adf_csr_fetch_and_and(csr, ADF_4XXX_REG_RF_PARITY_ERR_EN,
			      ~ADF_4XXX_REG_RF_PARITY_ERR_MASK);

	/* Disable Debug Parity Error RF interrupt */
	adf_csr_fetch_and_and(csr, ADF_4XXX_REG_RF_PARITY_ERR_INTEN,
			      ~ADF_4XXX_REG_RF_PARITY_ERR_MASK);

        /* Disable RF Parity Error reporting in Shared RAM */
	adf_csr_fetch_and_and(csr, ADF_4XXX_SSMSOFTERRORPARITYMASK_SRC,
			      ~ADF_4XXX_SSMSOFTERRORPARITY_SRC_MASK);

	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SSMSOFTERRORPARITYMASK_ATH_CPH,
			     ADF_4XXX_SPPPARERRMSK_ATH_CPH_MASK);
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SSMSOFTERRORPARITYMASK_CPR_XLT,
			     ADF_4XXX_SPPPARERRMSK_CPR_XLT_MASK);
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SSMSOFTERRORPARITYMASK_DCPR_UCS,
			     ADF_4XXX_SPPPARERRMSK_DCPR_UCS_MASK);
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SSMSOFTERRORPARITYMASK_PKE,
			     ADF_4XXX_SPPPARERRMSK_PKE_MASK);
}

static void disable_ae_errors_reporting(void __iomem *csr,
					const unsigned long ae_mask)
{
	u32 bit_iterator;

	/* Disable HI AE Uncorrectable Error Reporting */
	adf_csr_fetch_and_and(csr, ADF_4XXX_HIAEUNCERRLOGENABLE_CPP0,
			      ~ADF_4XXX_HIAEUNCERRLOGENABLE_CPP0_MASK);

	/* Disable HI AE Correctable Error Reporting */
	adf_csr_fetch_and_and(csr,
			      ADF_4XXX_HIAECORERRLOGENABLE_CPP0,
			      ~ADF_4XXX_HIAECORERRLOGENABLE_CPP0_MASK);

	/* Disable Acceleration Engine error detection & correction */
	for_each_set_bit(bit_iterator, &ae_mask, ADF_4XXX_MAX_ACCELENGINES) {
		adf_csr_fetch_and_and(csr,
				      ADF_4XXX_AE_CTX_ENABLES(bit_iterator),
				      ~ADF_4XXX_ENABLE_AE_ECC_ERR);
	}
}

static void disable_ssm_errors_reporting(void __iomem *csr,
					 const unsigned long accel_mask)
{
	u32 bit_iterator;

	for_each_set_bit(bit_iterator, &accel_mask, ADF_4XXX_MAX_ACCELERATORS) {
		/* Disable shared memory error detection & correction */
		adf_csr_fetch_and_and(csr, ADF_4XXX_SSMFEATREN(bit_iterator),
				      ~(ADF_4XXX_SSMFEATREN_UE_MASK |
				      ADF_4XXX_SSMFEATREN_CE_MASK));

		/* Disable SSM interrupts - ECC, CPP and SER */
		adf_csr_fetch_and_and(csr, ADF_4XXX_INTMASKSSM(bit_iterator),
				      ~(ADF_4XXX_INTMASKSSM_UE |
					ADF_4XXX_INTMASKSSM_CERR));
	}

	/* Disable SSM soft parity errors */
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SPPPARERRMSK_ATH_CPH,
			     ADF_4XXX_SPPPARERRMSK_ATH_CPH_MASK);
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SPPPARERRMSK_CPR_XLT,
			     ADF_4XXX_SPPPARERRMSK_CPR_XLT_MASK);
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SPPPARERRMSK_DCPR_UCS,
			     ADF_4XXX_SPPPARERRMSK_DCPR_UCS_MASK);
	adf_csr_fetch_and_or(csr,
			     ADF_4XXX_SPPPARERRMSK_PKE,
			     ADF_4XXX_SPPPARERRMSK_PKE_MASK);

	/* Disable SER detection in SER_err_ssmsh register according to RAS
	 * compliance
	 */
	adf_csr_fetch_and_and(csr, ADF_4XXX_SER_EN_SSMSH,
			      ~(ADF_4XXX_SER_EN_SSMSH_UCERR_MASK |
			      ADF_4XXX_SER_EN_SSMSH_CERR_MASK));

	for_each_set_bit(bit_iterator, &accel_mask, ADF_4XXX_MAX_ACCELERATORS) {
		/* Mask Slice Hang interrupts. */
		adf_csr_fetch_and_or(csr,
				     ADF_4XXX_SHINTMASKSSM_ATH_CPH_OFFSET(bit_iterator),
				     ADF_4XXX_SHINTMASKSSM_ATH_CPH_MASK);
		adf_csr_fetch_and_or(csr, ADF_4XXX_SHINTMASKSSM_CPR_XLT_OFFSET(bit_iterator),
				     ADF_4XXX_SHINTMASKSSM_CPR_XLT_MASK);
		adf_csr_fetch_and_or(csr, ADF_4XXX_SHINTMASKSSM_DCPR_UCS_OFFSET(bit_iterator),
				     ADF_4XXX_SHINTMASKSSM_DCPR_UCS_MASK);
		adf_csr_fetch_and_or(csr, ADF_4XXX_SHINTMASKSSM_PKE_OFFSET(bit_iterator),
				     ADF_4XXX_SHINTMASKSSM_PKE_MASK);
	}
}

static void disable_ti_ri_errors_reporting(void __iomem *csr)
{
	/* Disable error detection and reporting in TIMISCSTS */
	adf_csr_fetch_and_and(csr, ADF_4XXX_TIMISCCTL,
			      ~ADF_4XXX_TIMISCCTL_ERREN_MASK);

	/* Disable error handling in RI, TI CPP interface control registers */
	adf_csr_fetch_and_and(csr, ADF_4XXX_RICPPINTCTL, ~ADF_4XXX_RICPP_EN);
	adf_csr_fetch_and_and(csr, ADF_4XXX_TICPPINTCTL, ~ADF_4XXX_TICPP_EN);

	/* Disable RI Internal Memory & RF Parity Errors */
	adf_csr_fetch_and_and(csr, ADF_4XXX_RI_MEM_PAR_ERR_EN0,
			      ~ADF_4XXX_RI_MEM_PAR_ERR_EN0_UC_MASK);

	/* Disable TI Internal Memory Parity Error */
	adf_csr_fetch_and_or(csr, ADF_4XXX_TI_CI_PAR_ERR_MASK,
			     ADF_4XXX_TI_CI_PAR_ERR_RW_BITMASK);
	adf_csr_fetch_and_or(csr, ADF_4XXX_TI_PULL0FUB_PAR_ERR_MASK,
			     ADF_4XXX_TI_PULL0FUB_PAR_ERR_RW_BITMASK);
	adf_csr_fetch_and_or(csr, ADF_4XXX_TI_PUSHFUB_PAR_ERR_MASK,
			     ADF_4XXX_TI_PUSHFUB_PAR_ERR_RW_BITMASK);
	adf_csr_fetch_and_or(csr, ADF_4XXX_TI_CD_PAR_ERR_MASK,
			     ADF_4XXX_TI_CD_PAR_ERR_BITMASK);
	adf_csr_fetch_and_or(csr, ADF_4XXX_TI_TRNSB_PAR_ERR_MASK,
			     ADF_4XXX_TI_TRNSB_PAR_ERR_BITMASK);

	/* Disable RL Internal Memory Parity Error reporting */
	adf_csr_fetch_and_or(csr, ADF_4XXX_RL_PAR_ERR_MASK,
			     ADF_4XXX_RL_PAR_ERR_BITMASK);

	/* Disable QM Internal Memory Parity Error reporting */
	adf_csr_fetch_and_or(csr, ADF_4XXX_QM_PAR_ERR_MASK,
			     ADF_4XXX_QM_PAR_ERR_BITMASK);
}

static void disable_cpp_errors_reporting(void __iomem *csr)
{
	/* Disable CPP CFC uncorrectable errors */
	adf_csr_fetch_and_and(csr, ADF_4XXX_CPP_CFC_ERR_CTRL,
			      ~ADF_4XXX_CPP_CFC_UE);
}

static void disable_misc_errors_reporting(void __iomem *csr)
{
	/* Disable IOSF Primary Command Parity Error reporting */
	adf_csr_fetch_and_and(csr, ADF_4XXX_RIMISCCTL,
			      ~ADF_4XXX_RIMISCCTL_MASK);

	/* Disable HI CPP Agents Command Parity Error Reporting */
	adf_csr_fetch_and_and(csr, ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE,
			      ~ADF_4XXX_HICPPAGENTCMDPARERRLOGENABLE_MASK);
}

static void adf_4xxx_disable_ras(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	const unsigned long accel_mask = hw_data->accel_mask;
	const unsigned long ae_mask = hw_data->ae_mask;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)];
	void __iomem *csr = misc_bar->virt_addr;

	disable_reporting_to_errsoux(csr);
	disable_aram_errors_reporting(csr);
	disable_rf_errors_reporting(csr);
	disable_ae_errors_reporting(csr, ae_mask);
	disable_ssm_errors_reporting(csr, accel_mask);
	disable_ti_ri_errors_reporting(csr);
	disable_cpp_errors_reporting(csr);
	disable_misc_errors_reporting(csr);
}

void adf_4xxx_exit_ras(struct adf_accel_dev *accel_dev)
{
	adf_4xxx_disable_ras(accel_dev);

	if (accel_dev->ras_counters) {
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_correctable);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_uncorrectable);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_fatal);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_reset);
		kfree(accel_dev->ras_counters);
		accel_dev->ras_counters = NULL;
	}
}

static inline void adf_process_errsou0(struct adf_accel_dev *accel_dev,
				       void __iomem *csr, u32 errsou)
{
	u32 bit_iterator;
	const unsigned long aecorrerr =
		ADF_CSR_RD(csr, ADF_4XXX_HIAECORERRLOG_CPP0);

	if (unlikely(!(aecorrerr & ADF_4XXX_HIAECORERRLOG_CPP0_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in HIMECERRLOG_CPP0: 0x%lx\n",
			 aecorrerr);
		return;
	}

	dev_warn(&GET_DEV(accel_dev), "ERRSOU0 CERR: 0x%x\n", errsou);

	/* For each correctable error in AE, increment RAS counter */
	for_each_set_bit(bit_iterator, &aecorrerr, ADF_4XXX_MAX_ACCELENGINES) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);
		dev_warn(&GET_DEV(accel_dev),
			 "Correctable error detected in AE%d\n", bit_iterator);
	}

	/* Clear interrupt from ERRSOU0 */
	ADF_CSR_WR(csr, ADF_4XXX_HIAECORERRLOG_CPP0, aecorrerr);
}

static inline void adf_handle_cpp0_aeunc(struct adf_accel_dev *accel_dev,
					 void __iomem *csr)
{
	u32 bit_iterator;
	const unsigned long aeuncorerr =
		ADF_CSR_RD(csr, ADF_4XXX_HIAEUNCERRLOG_CPP0);

	if (unlikely(!(aeuncorerr & ADF_4XXX_HIAEUNCERRLOG_CPP0_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in HIAEUNCERRLOG_CPP0: 0x%lx\n",
			 aeuncorerr);
		return;
	}

	/* For each Uncorrectable error in AE, increment RAS counter */
	for_each_set_bit(bit_iterator, &aeuncorerr, ADF_4XXX_MAX_ACCELENGINES) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		dev_warn(&GET_DEV(accel_dev),
			 "Uncorrectable error detected in AE%d\n", bit_iterator);
	}

	ADF_CSR_WR(csr, ADF_4XXX_HIAEUNCERRLOG_CPP0,
		   aeuncorerr);
}

static inline void adf_handle_cppcmdparerr(struct adf_accel_dev *accel_dev,
					   void __iomem *csr)
{
	u32 cmdparerr = ADF_CSR_RD(csr, ADF_4XXX_HICPPAGENTCMDPARERRLOG);

	if (unlikely(!(cmdparerr &
			  ADF_4XXX_HICPPAGENTCMDPARERRLOG_UC_ERR_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in HICPPAGENTCMDPARERRLOG: 0x%x\n",
			 cmdparerr);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "HI CPP Agents Command Parity Error: 0x%x\n", cmdparerr);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_HICPPAGENTCMDPARERRLOG,
		   cmdparerr);
}

static inline void adf_handle_ri_mem_par_err(struct adf_accel_dev *accel_dev,
					     void __iomem *csr)
{
	u32 rimem_parerr_sts = ADF_CSR_RD(csr, ADF_4XXX_RIMEM_PARERR_STS);

	if (unlikely(!(rimem_parerr_sts &
		ADF_4XXX_RI_MEM_PAR_ERR_EN0_UC_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in RIMEM_PARERR_STS: 0x%x\n",
			 rimem_parerr_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "RI Memory Parity Error: 0x%x\n", rimem_parerr_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_RIMEM_PARERR_STS,
		   rimem_parerr_sts);
}

static inline void adf_handle_ti_ci_par_sts(struct adf_accel_dev *accel_dev,
					    void __iomem *csr)
{
	u32 ti_ci_par_sts = ADF_CSR_RD(csr, ADF_4XXX_TI_CI_PAR_STS);

	if (unlikely(!(ti_ci_par_sts & ADF_4XXX_TI_CI_PAR_ERR_BITMASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in TI_CI_PAR_STS: 0x%x\n",
			 ti_ci_par_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "TI Memory Parity Error: 0x%x\n", ti_ci_par_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_TI_CI_PAR_STS,
		   ti_ci_par_sts);
}

static
inline void adf_handle_ti_pull0fub_par_sts(struct adf_accel_dev *accel_dev,
					   void __iomem *csr)
{
	u32 ti_pullfub_par_sts = ADF_CSR_RD(csr, ADF_4XXX_TI_PULL0FUB_PAR_STS);

	if (unlikely(!(ti_pullfub_par_sts &
			  ADF_4XXX_TI_PULL0FUB_PAR_ERR_BITMASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in TI_PULL0FUB_PAR_STS: 0x%x\n",
			 ti_pullfub_par_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "TI Pull Parity Error: 0x%x\n", ti_pullfub_par_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_TI_PULL0FUB_PAR_STS,
		   ti_pullfub_par_sts);
}

static
inline void adf_handle_ti_pushfub_par_sts(struct adf_accel_dev *accel_dev,
					  void __iomem *csr)
{
	u32 ti_pushfub_par_sts = ADF_CSR_RD(csr, ADF_4XXX_TI_PUSHFUB_PAR_STS);

	if (unlikely(!(ti_pushfub_par_sts &
			  ADF_4XXX_TI_PUSHFUB_PAR_ERR_BITMASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in TI_PUSHFUB_PAR_STS: 0x%x\n",
			 ti_pushfub_par_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "TI Push Parity Error: 0x%x\n", ti_pushfub_par_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_TI_PUSHFUB_PAR_STS,
		   ti_pushfub_par_sts);
}

static inline void adf_handle_ti_cd_par_sts(struct adf_accel_dev *accel_dev,
					    void __iomem *csr)
{
	u32 ti_cd_par_sts = ADF_CSR_RD(csr, ADF_4XXX_TI_CD_PAR_STS);

	if (unlikely(!(ti_cd_par_sts & ADF_4XXX_TI_CD_PAR_ERR_BITMASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in TI_CD_PAR_STS: 0x%x\n",
			 ti_cd_par_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "TI CD Parity Error: 0x%x\n", ti_cd_par_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_TI_CD_PAR_STS,
		   ti_cd_par_sts);
}

static inline void adf_handle_ti_trnsb_par_sts(struct adf_accel_dev *accel_dev,
					       void __iomem *csr)
{
	u32 ti_trnsb_par_sts = ADF_CSR_RD(csr, ADF_4XXX_TI_TRNSB_PAR_STS);

	if (unlikely(!(ti_trnsb_par_sts & ADF_4XXX_TI_TRNSB_PAR_ERR_BITMASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in TI_TRNSB_PAR_STS: 0x%x\n",
			 ti_trnsb_par_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "TI TRNSB Parity Error: 0x%x\n", ti_trnsb_par_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_TI_TRNSB_PAR_STS,
		   ti_trnsb_par_sts);
}

static inline void adf_handle_rl_par_sts(struct adf_accel_dev *accel_dev,
					 void __iomem *csr)
{
	u32 rl_par_sts = ADF_CSR_RD(csr, ADF_4XXX_RL_PAR_STS);

	if (unlikely(!(rl_par_sts & ADF_4XXX_RL_PAR_ERR_BITMASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in RL_PAR_STS: 0x%x\n",
			 rl_par_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "RL Parity Error: 0x%x\n", rl_par_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_RL_PAR_STS,
		   rl_par_sts);
}

static inline void adf_handle_qm_par_sts(struct adf_accel_dev *accel_dev,
					 void __iomem *csr)
{
	u32 qm_par_sts = ADF_CSR_RD(csr, ADF_4XXX_QM_PAR_STS);

	if (unlikely(!(qm_par_sts & ADF_4XXX_QM_PAR_ERR_BITMASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in QM_PAR_STS: 0x%x\n",
			 qm_par_sts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "QM Parity Error: 0x%x\n", qm_par_sts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_QM_PAR_STS,
		   qm_par_sts);
}

static inline void adf_handle_iosfp_cmd_parerr(struct adf_accel_dev *accel_dev,
					       void __iomem *csr)
{
	u32 rimiscsts = ADF_CSR_RD(csr, ADF_4XXX_RIMISCSTS);

	if (unlikely(!(rimiscsts & ADF_4XXX_RIMISCSTS_UC_ERR_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in RIMISCSTS: 0x%x\n",
			 rimiscsts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "Command Parity error detected on IOSFP Command to QAT: 0x%x\n",
		 rimiscsts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_RIMISCSTS,
		   rimiscsts);
}

static inline void adf_process_errsou1(struct adf_accel_dev *accel_dev,
				       void __iomem *csr, u32 errsou,
				       bool *reset_required)
{
	dev_warn(&GET_DEV(accel_dev), "ERRSOU1 UERR: 0x%x\n", errsou);

	if (errsou & ADF_4XXX_ERRSOU1_CPP0_AEUNC_MASK)
		adf_handle_cpp0_aeunc(accel_dev, csr);

	if (errsou & ADF_4XXX_ERRSOU1_CPPCMDPARERR_MASK)
		adf_handle_cppcmdparerr(accel_dev, csr);

	if (errsou & ADF_4XXX_ERRSOU1_RI_MEM_PAR_ERR_MASK)
		adf_handle_ri_mem_par_err(accel_dev, csr);

	if (errsou & ADF_4XXX_ERRSOU1_TI_MEM_PAR_ERR_MASK) {
		adf_handle_ti_ci_par_sts(accel_dev, csr);
		adf_handle_ti_pull0fub_par_sts(accel_dev, csr);
		adf_handle_ti_pushfub_par_sts(accel_dev, csr);
		adf_handle_ti_cd_par_sts(accel_dev, csr);
		adf_handle_ti_trnsb_par_sts(accel_dev, csr);
		adf_handle_rl_par_sts(accel_dev, csr);
		adf_handle_qm_par_sts(accel_dev, csr);
	}

	if (errsou & ADF_4XXX_ERRSOU1_IOSFP_CMD_PARERR_MASK) {
		*reset_required = true;
		adf_handle_iosfp_cmd_parerr(accel_dev, csr);
	}
}

static inline void adf_handle_uerrssmsh(struct adf_accel_dev *accel_dev,
					u32 accel_id, void __iomem *csr)
{
	u32 reg = ADF_CSR_RD(csr, ADF_4XXX_UERRSSMSH(accel_id));

	reg &= ADF_4XXX_UERRSSMSH_UERR_MASK;
	if (reg) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_UERRSSMSH(accel_id), reg);
	}
}

static inline void adf_handle_perr_ue(struct adf_accel_dev *accel_dev,
				      void __iomem *csr)
{
	u32 reg = ADF_CSR_RD(csr, ADF_4XXX_PPERR);

	reg &= ADF_4XXX_PPERR_PERR_MASK;
	if (reg) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_PPERR, reg);
	}
}

static inline void adf_handle_spppar_err_ue(struct adf_accel_dev *accel_dev,
					    void __iomem *csr)
{
	u32 pullcmdparerr_ath_cph =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLCMDPARERR_ATH_CPH);
	u32 pullcmdparerr_cpr_xlt =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLCMDPARERR_CPR_XLT);
	u32 pullcmdparerr_dcpr_ucs =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLCMDPARERR_DCPR_UCS);
	u32 pullcmdparerr_pke =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLCMDPARERR_PKE);

	u32 pulldataparerr_ath_cph =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLDATAPARERR_ATH_CPH);
	u32 pulldataparerr_cpr_xlt =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLDATAPARERR_CPR_XLT);
	u32 pulldataparerr_dcpr_ucs =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLDATAPARERR_DCPR_UCS);
	u32 pulldataparerr_pke =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPULLDATAPARERR_PKE);

	u32 pushcmdparerr_ath_cph =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHCMDPARERR_ATH_CPH);
	u32 pushcmdparerr_cpr_xlt =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHCMDPARERR_CPR_XLT);
	u32 pushcmdparerr_dcpr_ucs =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHCMDPARERR_DCPR_UCS);
	u32 pushcmdparerr_pke =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHCMDPARERR_PKE);

	u32 pushdataparerr_ath_cph =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHDATAPARERR_ATH_CPH);
	u32 pushdataparerr_cpr_xlt =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHDATAPARERR_CPR_XLT);
	u32 pushdataparerr_dcpr_ucs =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHDATAPARERR_DCPR_UCS);
	u32 pushdataparerr_pke =
		ADF_CSR_RD(csr, ADF_4XXX_SPPPUSHDATAPARERR_PKE);

	/* pull command parity errors */
	if (pullcmdparerr_ath_cph & ADF_4XXX_SPP_PARERR_ATH_CPH_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLCMDPARERR_ATH_CPH,
			   pullcmdparerr_ath_cph);
	}

	if (pullcmdparerr_cpr_xlt & ADF_4XXX_SPP_PARERR_CPR_XLT_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLCMDPARERR_CPR_XLT,
			   pullcmdparerr_cpr_xlt);
	}

	if (pullcmdparerr_dcpr_ucs & ADF_4XXX_SPP_PARERR_DCPR_UCS_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLCMDPARERR_DCPR_UCS,
			   pullcmdparerr_dcpr_ucs);
	}

	if (pullcmdparerr_pke & ADF_4XXX_SPP_PARERR_PKE_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLCMDPARERR_PKE,
			   pullcmdparerr_pke);
	}

	/* pull data parity errors */
	if (pulldataparerr_ath_cph & ADF_4XXX_SPP_PARERR_ATH_CPH_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLDATAPARERR_ATH_CPH,
			   pulldataparerr_ath_cph);
	}

	if (pulldataparerr_cpr_xlt & ADF_4XXX_SPP_PARERR_CPR_XLT_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLDATAPARERR_CPR_XLT,
			   pulldataparerr_cpr_xlt);
	}

	if (pulldataparerr_dcpr_ucs & ADF_4XXX_SPP_PARERR_DCPR_UCS_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLDATAPARERR_DCPR_UCS,
			   pulldataparerr_dcpr_ucs);
	}

	if (pulldataparerr_pke & ADF_4XXX_SPP_PARERR_PKE_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPULLDATAPARERR_PKE,
			   pulldataparerr_pke);
	}

	/* push command parity errors */
	if (pushcmdparerr_ath_cph & ADF_4XXX_SPP_PARERR_ATH_CPH_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHCMDPARERR_ATH_CPH,
			   pushcmdparerr_ath_cph);
	}

	if (pushcmdparerr_cpr_xlt & ADF_4XXX_SPP_PARERR_CPR_XLT_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHCMDPARERR_CPR_XLT,
			   pushcmdparerr_cpr_xlt);
	}

	if (pushcmdparerr_dcpr_ucs & ADF_4XXX_SPP_PARERR_DCPR_UCS_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHCMDPARERR_DCPR_UCS,
			   pushcmdparerr_dcpr_ucs);
	}

	if (pushcmdparerr_pke & ADF_4XXX_SPP_PARERR_PKE_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHCMDPARERR_PKE,
			   pushcmdparerr_pke);
	}

	/* push data parity errors */
	if (pushdataparerr_ath_cph & ADF_4XXX_SPP_PARERR_ATH_CPH_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHDATAPARERR_ATH_CPH,
			   pushdataparerr_ath_cph);
	}

	if (pushdataparerr_cpr_xlt & ADF_4XXX_SPP_PARERR_CPR_XLT_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHDATAPARERR_CPR_XLT,
			   pushdataparerr_cpr_xlt);
	}

	if (pushdataparerr_dcpr_ucs & ADF_4XXX_SPP_PARERR_DCPR_UCS_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHDATAPARERR_DCPR_UCS,
			   pushdataparerr_dcpr_ucs);
	}

	if (pushdataparerr_pke & ADF_4XXX_SPP_PARERR_PKE_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SPPPUSHDATAPARERR_PKE,
			   pushdataparerr_pke);
	}
}

static inline void adf_handle_cpppar_err_ue(struct adf_accel_dev *accel_dev,
					    u32 accel_id, void __iomem *csr)
{
	u32 reg = ADF_CSR_RD(csr, ADF_4XXX_SSMCPPERR(accel_id));

	reg &= ADF_4XXX_SSMCPPERR_UCERR_MASK;
	if (reg) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SSMCPPERR(accel_id), reg);
	}
}

static inline void adf_handle_ser_err_ssmsh(struct adf_accel_dev *accel_dev,
					    void __iomem *csr,
					    bool *reset_required)
{
	u32 reg = ADF_CSR_RD(csr, ADF_4XXX_SER_ERR_SSMSH);

	reg &= (ADF_4XXX_SER_ERR_SSMSH_FATERR_MASK |
		ADF_4XXX_SER_ERR_SSMSH_UCERR_MASK |
		ADF_4XXX_SER_ERR_SSMSH_CERR_MASK);

	if (reg & ADF_4XXX_SER_ERR_SSMSH_FATERR_MASK) {
		*reset_required = true;
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_FATAL]);
	}

	if (reg & ADF_4XXX_SER_ERR_SSMSH_UCERR_MASK)
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);

	if (reg & ADF_4XXX_SER_ERR_SSMSH_CERR_MASK)
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);

	ADF_CSR_WR(csr, ADF_4XXX_SER_ERR_SSMSH, reg);
}

static inline void adf_handle_rf_parr_err_ue(struct adf_accel_dev *accel_dev,
					     void __iomem *csr)
{
	u32 reg = ADF_CSR_RD(csr, ADF_4XXX_SSMSOFTERRORPARITY_SRC);

	reg &= ADF_4XXX_SSMSOFTERRORPARITY_SRC_MASK;
	if (reg) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		ADF_CSR_WR(csr, ADF_4XXX_SSMSOFTERRORPARITY_SRC,
			   reg);
	}
	dev_warn(&GET_DEV(accel_dev), "SSMSOFTERRORPARITY_SRC: 0x%x\n", reg);
}

static inline void adf_handle_sh_cerr(struct adf_accel_dev *accel_dev,
				      u32 accel_id, void __iomem *csr)
{
	u32 reg = ADF_CSR_RD(csr, ADF_4XXX_CERRSSMSH(accel_id));

	reg &= ADF_4XXX_ERRSSMSH_CERR;
	if (reg) {
		dev_warn(&GET_DEV(accel_dev),
			 "Error in SSM shared RAM memory\n");
		ADF_CSR_WR(csr, ADF_4XXX_CERRSSMSH(accel_id),
			   reg);
	}
	dev_warn(&GET_DEV(accel_dev), "CERRSSMSH: 0x%x\n", reg);
}

static inline void adf_handle_iaintstatssm(struct adf_accel_dev *accel_dev,
					   void __iomem *csr,
					   bool *reset_required)
{
	u32 accel = 0;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	unsigned long accel_mask = hw_device->accel_mask;

	for_each_set_bit(accel, &accel_mask, ADF_4XXX_MAX_ACCELERATORS) {
		u32 iastatssm = ADF_CSR_RD(csr, ADF_IAINTSTATSSM(accel));

		if (iastatssm & ADF_4XXX_IAINTSTATSSM_SH_UERR_MASK)
			adf_handle_uerrssmsh(accel_dev, accel, csr);

		if (iastatssm & ADF_4XXX_IAINTSTATSSM_PPERR_MASK)
			adf_handle_perr_ue(accel_dev, csr);

		if (iastatssm & ADF_4XXX_IAINTSTATSSM_SPPPAR_ERR_MASK)
			adf_handle_spppar_err_ue(accel_dev, csr);

		if (iastatssm & ADF_4XXX_IAINTSTATSSM_CPPPAR_ERR_MASK)
			adf_handle_cpppar_err_ue(accel_dev, accel, csr);

		if (iastatssm & (ADF_4XXX_SER_ERR_SSMSH_FATERR_MASK |
				 ADF_4XXX_IAINTSTATSSM_SER_UERR_MASK |
				 ADF_4XXX_IAINTSTATSSM_SER_CERR_MASK)) {
			adf_handle_ser_err_ssmsh(accel_dev, csr,
						 reset_required);
		}

		if (iastatssm & ADF_4XXX_IAINTSTATSSM_RFPAR_ERR_MASK)
			adf_handle_rf_parr_err_ue(accel_dev, csr);

		if (iastatssm & ADF_4XXX_IAINTSTATSSM_SLICEHANG_ERR_MASK)
			adf_4xxx_handle_slice_hang_error(accel_dev, accel, csr);

		/* Handling of CERRs reported to IAINTSTATSSM */
		if (iastatssm & ADF_4XXX_IAINTSTATSSM_SH_CERR_MASK) {
			adf_handle_sh_cerr(accel_dev, accel, csr);
			atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);
		}

		dev_warn(&GET_DEV(accel_dev), "IAINTSTATSSM: 0x%x\n",
			 iastatssm);
		ADF_CSR_WR(csr, ADF_IAINTSTATSSM(accel), iastatssm);
	}
}

static inline void adf_handle_cpp_cfc_err_uerr(struct adf_accel_dev *accel_dev,
					       void __iomem *csr)
{
	u32 reg = ADF_CSR_RD(csr, ADF_4XXX_CPP_CFC_ERR_STATUS);

	reg &= ADF_4XXX_CPP_CFC_UE;
	if (reg)
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	dev_warn(&GET_DEV(accel_dev), "CPP_CFC_ERR_STATUS: 0x%x\n", reg);
}

static inline void adf_process_errsou2(struct adf_accel_dev *accel_dev,
				       void __iomem *csr, u32 errsou,
				       bool *reset_required)
{
	dev_warn(&GET_DEV(accel_dev), "ERRSOU2 ERR: 0x%x\n", errsou);

	if (errsou & ADF_4XXX_ERRSOU2_CFC0_SSM0)
		adf_handle_iaintstatssm(accel_dev, csr, reset_required);

	if (errsou & ADF_4XXX_ERRSOU2_CFC0_PUSHPULL_ERR)
		dev_err(&GET_DEV(accel_dev),
			"CFC Push/Pull error detected\n");

	if (errsou & ADF_4XXX_ERRSOU2_CFC0_ATTN_INT)
		adf_handle_cpp_cfc_err_uerr(accel_dev, csr);
}

static inline void adf_handle_ricppintsts(struct adf_accel_dev *accel_dev,
					  void __iomem *csr)
{
	u32 ricppintsts = ADF_CSR_RD(csr, ADF_4XXX_RICPPINTSTS);

	if (unlikely(!(ricppintsts & ADF_4XXX_RICPPINTSTS_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in RICPPINTSTS: 0x%x\n",
			 ricppintsts);
		return;
	}

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_RICPPINTSTS, ricppintsts);
	dev_warn(&GET_DEV(accel_dev),
		 "RI CPP Uncorrectable Error: 0x%x\n", ricppintsts);
}

static inline void adf_handle_ticppintsts(struct adf_accel_dev *accel_dev,
					  void __iomem *csr)
{
	u32 ticppintsts = ADF_CSR_RD(csr, ADF_4XXX_TICPPINTSTS);

	if (unlikely
		(!(ticppintsts & ADF_4XXX_TICPPINTSTS_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in TICPPINTSTS: 0x%x\n",
			 ticppintsts);
		return;
	}

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_TICPPINTSTS, ticppintsts);
	dev_warn(&GET_DEV(accel_dev),
		 "TI CPP Uncorrectable Error: 0x%x\n", ticppintsts);
}

static inline void adf_handle_timiscsts(struct adf_accel_dev *accel_dev,
					void __iomem *csr,
					bool *reset_required)
{
	u32 timiscsts = ADF_CSR_RD(csr, ADF_4XXX_TIMISCSTS);

	if (unlikely(!(timiscsts & ADF_4XXX_TIMISCSTS_ERR_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in TIMISCSTS: 0x%x\n",
			 timiscsts);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "Internal fatal error in Transmit Interface: 0x%x\n",
		 timiscsts);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_FATAL]);
	*reset_required = true;
}

static inline void adf_handle_aramuerr(struct adf_accel_dev *accel_dev,
				       void __iomem *csr)
{
	u32 aramuerr = ADF_CSR_RD(csr, ADF_4XXX_ARAMUERR);

	if (unlikely
		(!(aramuerr & ADF_4XXX_ARAMUERR_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in ARAMUERR: 0x%x\n",
			 aramuerr);
		return;
	}

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_ARAMUERR, aramuerr);
	dev_warn(&GET_DEV(accel_dev),
		 "ARAM register Uncorrectable Error: 0x%x\n", aramuerr);
}

static inline void adf_handle_reg_cppmemtgterr(struct adf_accel_dev *accel_dev,
					       void __iomem *csr)
{
	u32 cppmemtgterr = ADF_CSR_RD(csr, ADF_4XXX_CPPMEMTGTERR);

	if (unlikely
		(!(cppmemtgterr & ADF_4XXX_REG_CPPMEMTGTERR_UE_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in REG_CPPMEMTGTERR: 0x%x\n",
			 cppmemtgterr);
		return;
	}

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_CPPMEMTGTERR, cppmemtgterr);
	dev_warn(&GET_DEV(accel_dev),
		 "Misc Memory Target Uncorrectable Error: 0x%x\n",
		 cppmemtgterr);
}

static inline void adf_handle_reg_rf_parity_err_sts(struct adf_accel_dev *accel_dev,
						    void __iomem *csr)
{
	u32 parity_err = ADF_CSR_RD(csr, ADF_4XXX_REG_RF_PARITY_ERR_STS);

	if (unlikely
		(!(parity_err & ADF_4XXX_REG_RF_PARITY_ERR_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in REG_RF_PARITY_ERR_STS 0x%x\n",
			 parity_err);
		return;
	}

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
	ADF_CSR_WR(csr, ADF_4XXX_REG_RF_PARITY_ERR_STS, parity_err);
	dev_warn(&GET_DEV(accel_dev),
		 "Debug Parity Error Uncorrectable Error: 0x%x\n", parity_err);
}

static inline void adf_handle_reg_me_th_status(struct adf_accel_dev *accel_dev,
					       void __iomem *csr)
{
	u32 i;

	for (i = 0; i < ADF_4XXX_REG_ME_TH_STATUS_NUM_ME_CLUSTER; i++) {
		u32 me_th_status = ADF_CSR_RD(csr, ADF_4XXX_REG_ME_TH_STATUS(i));

		if (me_th_status & ADF_4XXX_REG_ME_TH_STATUS_ME0_MASK) {
			dev_warn(&GET_DEV(accel_dev),
				 "ME(%u) thread error: 0x%x\n",
				 ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME0(i),
				 me_th_status);

			atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		}
		if (me_th_status & ADF_4XXX_REG_ME_TH_STATUS_ME1_MASK) {
			dev_warn(&GET_DEV(accel_dev),
				 "ME(%u) thread error: 0x%x\n",
				 ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME1(i),
				 me_th_status);

			atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		}
		if (me_th_status & ADF_4XXX_REG_ME_TH_STATUS_ME2_MASK) {
			dev_warn(&GET_DEV(accel_dev),
				 "ME(%u) thread error: 0x%x\n",
				 ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME2(i),
				 me_th_status);

			atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		}
		if (me_th_status & ADF_4XXX_REG_ME_TH_STATUS_ME3_MASK) {
			dev_warn(&GET_DEV(accel_dev),
				 "ME(%u) thread error: 0x%x\n",
				 ADF_4XXX_REG_ME_TH_STATUS_ACTUAL_ME3(i),
				 me_th_status);

			atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		}

		ADF_CSR_WR(csr, ADF_4XXX_REG_ME_TH_STATUS(i), me_th_status);
	}
}

static inline void adf_handle_atufaultstatus(struct adf_accel_dev *accel_dev,
					     void __iomem *csr)
{
	u32 i;

	for (i = 0; i < ADF_4XXX_ATUFAULTSTATUS_NUM_RING_PAIR; i++) {
		u32 atufaultstatus = ADF_CSR_RD(csr, ADF_4XXX_ATUFAULTSTATUS(i));

		if (atufaultstatus & ADF_4XXX_ATUFAULTSTATUS_INTFAULT_MASK) {
			dev_warn(&GET_DEV(accel_dev),
				 "Ring Pair (%u) ATU detected fault: 0x%x\n", i,
				 atufaultstatus);
			ADF_CSR_WR(csr, ADF_4XXX_ATUFAULTSTATUS(i),
				   atufaultstatus);
			atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR]);
		}
	}
}

static inline void adf_handle_reg_rlt_errlog(struct adf_accel_dev *accel_dev,
					     void __iomem *csr)
{
	u32 errlog = ADF_CSR_RD(csr, ADF_4XXX_RLT_ERRLOG);

	if (unlikely
		(!(errlog & ADF_4XXX_RLT_ERRLOG_STATUS_MASK))) {
		dev_warn(&GET_DEV(accel_dev),
			 "No active error bits in RLT_ERRLOG: 0x%x\n",
			 errlog);
		return;
	}

	dev_warn(&GET_DEV(accel_dev),
		 "Rate Limiter Correctable Error: 0x%x\n", errlog);
	ADF_CSR_WR(csr, ADF_4XXX_RLT_ERRLOG, errlog);
	atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);
}

static inline void adf_handle_aramcerr(struct adf_accel_dev *accel_dev,
				       void __iomem *csr)
{
	u32 aram_cerr = ADF_CSR_RD(csr, ADF_4XXX_ARAMCERR);

	if (aram_cerr & ADF_4XXX_ARAM_CERR_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);
		ADF_CSR_WR(csr, ADF_4XXX_ARAMCERR, aram_cerr);
	}
}

static inline void adf_process_errsou3(struct adf_accel_dev *accel_dev,
				       void __iomem *csr, u32 errsou,
				       bool *reset_required)
{
	dev_warn(&GET_DEV(accel_dev), "ERRSOU3 UERR: 0x%x\n", errsou);

	if (errsou & ADF_4XXX_RI_PPP_ERR_MASK)
		adf_handle_ricppintsts(accel_dev, csr);

	if (errsou & ADF_4XXX_TI_PPP_ERR_MASK)
		adf_handle_ticppintsts(accel_dev, csr);

	if (errsou & ADF_4XXX_ERRSOU3_TIMISC_MASK)
		adf_handle_timiscsts(accel_dev, csr, reset_required);

	if (errsou & ADF_4XXX_ERRSOU3_ARAM_UNCERR_MASK) {
		adf_handle_aramuerr(accel_dev, csr);
		adf_handle_reg_cppmemtgterr(accel_dev, csr);
		adf_handle_reg_rf_parity_err_sts(accel_dev, csr);
		adf_handle_reg_me_th_status(accel_dev, csr);
	}

	if (errsou & ADF_4XXX_ERRSOU3_ATUFAULTNOTIFY_MASK)
		adf_handle_atufaultstatus(accel_dev, csr);

	if (errsou & ADF_4XXX_ERRSOU3_RLTERROR_MASK)
		adf_handle_reg_rlt_errlog(accel_dev, csr);

	if (errsou & ADF_4XXX_ERRMSK3_CERR)
		adf_handle_aramcerr(accel_dev, csr);
}

bool adf_4xxx_ras_interrupts(struct adf_accel_dev *accel_dev,
			     bool *reset_required)
{
	bool handled = false;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	void __iomem *csr =
		GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)].virt_addr;
	u32 errsou = ADF_CSR_RD(csr, ADF_4XXX_ERRSOU0);

	*reset_required = false;

	if (errsou & ADF_4XXX_ERRMSK0_CERR) {
		adf_process_errsou0(accel_dev, csr, errsou);
		handled = true;
	}

	errsou = ADF_CSR_RD(csr, ADF_4XXX_ERRSOU1);
	if (errsou & ADF_4XXX_ERRMSK1_UERR) {
		/* Disable uncorrectable errors in ERRSOU1 */
		adf_csr_fetch_and_or(csr, ADF_4XXX_ERRMSK1,
				     ADF_4XXX_ERRMSK1_UERR);

		adf_process_errsou1(accel_dev, csr, errsou, reset_required);

		/* Enable uncorrectable errors in ERRSOU1
		 * if no reset is needed
		 */
		if (!(*reset_required))
			adf_csr_fetch_and_and(csr, ADF_4XXX_ERRMSK1,
					      ~ADF_4XXX_ERRMSK1_UERR);

		handled = true;
	}

	errsou = ADF_CSR_RD(csr, ADF_4XXX_ERRSOU2);
	if (errsou & ADF_4XXX_ERRMSK2_UERR) {
		/* Disable uncorrectable errors in ERRSOU2 */
		adf_csr_fetch_and_or(csr, ADF_4XXX_ERRMSK2,
				     ADF_4XXX_ERRMSK2_UERR);

		adf_process_errsou2(accel_dev, csr, errsou, reset_required);

		/* Enable uncorrectable errors in ERRSOU2
		 * if no reset is needed
		 */
		if (!(*reset_required))
			adf_csr_fetch_and_and(csr, ADF_4XXX_ERRMSK2,
					      ~ADF_4XXX_ERRMSK2_UERR);

		handled = true;
	}

	errsou = ADF_CSR_RD(csr, ADF_4XXX_ERRSOU3);
	if (errsou & (ADF_4XXX_ERRMSK3_UERR | ADF_4XXX_ERRMSK3_CERR)) {
		/* Disable uncorrectable errors in ERRSOU3 */
		adf_csr_fetch_and_or(csr, ADF_4XXX_ERRMSK3,
				     ADF_4XXX_ERRMSK3_UERR);

		adf_process_errsou3(accel_dev, csr, errsou, reset_required);

		/* Enable uncorrectable errors in ERRSOU3
		 * if no reset is needed
		 */
		if (!(*reset_required))
			adf_csr_fetch_and_and(csr, ADF_4XXX_ERRMSK3,
					      ~ADF_4XXX_ERRMSK3_UERR);

		handled = true;
	}

	return handled;
}
