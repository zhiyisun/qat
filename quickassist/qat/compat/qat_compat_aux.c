// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Intel Corporation */
#ifdef QAT_NO_AUX
#include "qat_compat_aux.h"

int adf_add_aux_dev(struct adf_accel_dev *accel_dev)
{
	return -EFAULT;
}

int adf_del_aux_dev(struct adf_accel_dev *accel_dev)
{
	return -EFAULT;
}

int adf_enable_aux_dev(struct adf_accel_dev *accel_dev)
{
	return -EFAULT;
}

int adf_add_vf_aux_dev(struct adf_accel_dev *accel_dev)
{
	return -EFAULT;
}

int adf_del_vf_aux_dev(struct adf_accel_dev *accel_dev)
{
	return -EFAULT;
}
#endif /* QAT_NO_AUX */
