/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2018, 2021 Intel Corporation */

#ifndef ADF_RAS_H
#define ADF_RAS_H

struct adf_accel_dev;

bool adf_4xxx_ras_interrupts(struct adf_accel_dev *accel_dev,
			     bool *reset_required);

int adf_4xxx_init_ras(struct adf_accel_dev *accel_dev);

void adf_4xxx_exit_ras(struct adf_accel_dev *accel_dev);

#endif /* ADF_RAS_H */

