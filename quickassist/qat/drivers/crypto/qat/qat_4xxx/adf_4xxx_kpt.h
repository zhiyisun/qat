/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2019 - 2021 Intel Corporation */
#ifndef ADF_4XXX_KPT_H_
#define ADF_4XXX_KPT_H_

struct adf_accel_dev;
int adf_4xxx_init_kpt(struct adf_accel_dev *accel_dev);
int adf_4xxx_config_kpt(struct adf_accel_dev *accel_dev);
#endif
