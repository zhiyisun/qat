/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2020 - 2022 Intel Corporation */

#include "adf_sla.h"
#include "adf_cfg_common.h"
#include "adf_common_drv.h"
#include "adf_cfg_strings.h"
#include "adf_cfg.h"
#include "icp_qat_hw.h"
#include "adf_gen4_rl.h"

int adf_sla_create(struct adf_user_sla *sla)
{
	/* Unsupported */
	pr_err("QAT: Rate Limiting unsupported for device\n");
	return -1;
}

int adf_sla_update(struct adf_user_sla *sla)
{
	/* Unsupported */
	pr_err("QAT: Rate Limiting unsupported for device\n");
	return -1;
}

int adf_sla_delete(struct adf_user_sla *sla)
{
	/* Unsupported */
	pr_err("QAT: Rate Limiting unsupported for device\n");
	return -1;
}

int adf_sla_get_caps(struct adf_user_sla_caps *sla_caps)
{
	/* Unsupported */
	pr_err("QAT: Rate Limiting unsupported for device\n");
	return -1;
}

int adf_sla_get_list(struct adf_user_slas *slas)
{
	/* Unsupported */
	pr_err("QAT: Rate Limiting unsupported for device\n");
	return -1;
}

/*
 * adf_rate_limiting_init() - Start rate limit gathering and init
 * sla data structure
 * @accel_dev:    Pointer to acceleration device.
 *
 * Function checks if rate limiting feature is enabled for the device.
 * Starts rate limit gathering and initializes sla data structures for devices
 * that supports rate limiting.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_rate_limiting_init(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);

	/* If accel dev is VF, return 0 */
	if (accel_dev->is_vf)
		return 0;

	/* If rate limiting is not supported, return 0 */
	if (!(hw_data->accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_RL))
		return 0;

	if (hw_data->init_rl_v2 && hw_data->init_rl_v2(accel_dev)) {
		hw_data->accel_capabilities_mask &= ~ICP_ACCEL_CAPABILITIES_RL;
		dev_err(&GET_DEV(accel_dev),
			"Rate Limiting: Unsupported for device\n");
		return 0;
	}

	return 0;
}

/*
 * adf_rate_limiting_exit() - Delete the SLA entries and exit
 * @accel_dev:    Pointer to acceleration device.
 *
 * Function checks and deletes the entries of SLA and DU.
 *
 */
void adf_rate_limiting_exit(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);

	if (accel_dev->is_vf)
		return;

	/* If rate limiting is not supported, return */
	if (!(hw_data->accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_RL))
		return;

	if (hw_data->exit_rl_v2)
		hw_data->exit_rl_v2(accel_dev);
}
