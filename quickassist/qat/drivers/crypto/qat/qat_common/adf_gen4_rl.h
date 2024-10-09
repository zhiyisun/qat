/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2020 - 2022 Intel Corporation */

#ifndef ADF_GEN4_RL_V2_H_
#define ADF_GEN4_RL_V2_H_

#include "adf_sla_user.h"
#include "adf_cfg_common.h"

#define RL_MAX_ROOT 4
#define RL_MAX_CLUSTER 16
#define RL_MAX_LEAF 64
#define RL_MAX_RPS_PER_LEAF 16
#define RL_TOKEN_GRANULARITY_PCIEIN_BUCKET 0U
#define RL_TOKEN_GRANULARITY_PCIEOUT_BUCKET 0U
#define RL_VF_OFFSET 0x1
#define RL_PCI_DEV_OFFSET 0x3
#define RL_ROUND_MULTIPLE_MB 100
#define RL_ROUND_MULTIPLE_KO 1000

#define RL_TOKEN_PCIE_SIZE 64
#define RL_ASYM_TOKEN_SIZE 1024
#define RL_SLA_CONFIG_SIZE 64
#define RL_INPUT_FUNC_MAX 0xFF
/* Convert Mbits to bytes: mul(10^6) then div(8) */
#define RL_CONVERT_TO_BYTES ((u64)125000)

#define RL_SCANS_PER_SEC 954 /* For ~1.0485 ms scan period */
#define RL_PCIE_SCALE_FACTOR_DIV 100 /* 100% */
#define RL_PCIE_SCALE_FACTOR_MUL 102 /* Scaling factor */
#define RL_4XXX_SLICE_NUMBER 8
#define RL_4XXX_SYM_SLICE_NUM 2
#define RL_4XXX_DC_SLICE_NUM 3
#define RL_4XXX_ASYM_SLICE_NUM 6
#define RL_4XXX_CNV_SLICE 1

/* CSR offsets  */
#define RL_TOKEN_PCIEIN_BUCKET 0x00508800U
#define RL_TOKEN_PCIEOUT_BUCKET 0x00508804U
#define RL_RING2LEAF(i) (0x00508000U + ((i) * 0x4U))
#define RL_LEAF2CLUSTER(i) (0x00509000U + ((i) * 0x4U))
#define RL_CLUSTER2SERVICE(i) (0x00508818U + ((i) * 0x4U))

#define RL_VALIDATE_IR(rate, max) ((rate) > (max))
#define RL_VALIDATE_PCI_FUNK(sla) ((sla)->pci_addr.func > RL_INPUT_FUNC_MAX)
#define RL_VALIDATE_SLAU(rate, max) ((rate) > ((max)))
#define RL_VALIDATE_NON_ZERO(input) ((input) == 0)
#define RL_VALIDATE_RET_MAX(svc, slice_ref, max_tp) \
	(((svc) == ADF_SVC_ASYM) ? slice_ref : max_tp)
/*
 * First 5 bits is for the non unique id
 * 0 - 3  : root
 * 0 - 15 : cluster
 * 0 - 63 : leaves
 * In conjunction with next 2 bits, creates a unique id (bits 0 - 7)
 * 01 -	root
 * 10 -	cluster
 * 11 -	leaf
 */
#define RL_NODEID_TO_TREEID(node_id, node_type)                                \
	((node_id) | (((node_type) + 1) << 6))

/* Returns the node ID from the tree ID */
#define RL_TREEID_TO_NODEID(user_id) ((user_id) & 0x3F)

/* Returns the node ID from the tree ID for root node only */
#define RL_TREEID_TO_ROOT(user_id) ((user_id) & 0x03)

/* Returns the node type -> root, cluster, leaf */
#define RL_GET_NODE_TYPE(user_id) (((user_id) >> 6) - 1)

#define RL_RING_NUM(vf_func_num, vf_bank) (((vf_func_num) << (2)) + (vf_bank))

/* Internal context for each node in rate limiting tree */
struct rl_node_info {
	enum adf_user_node_type nodetype;
	u32 node_id; /* Unique ID */
	u32 rem_cir;
	u32 max_pir;
	bool sla_added;
	enum adf_svc_type svc_type;
	struct adf_user_sla sla; /* Copy of the user SLA */
	struct rl_node_info *parent;
};

/* Internal structure for tracking number of leafs/clusters */
struct rl_node_count {
	/* Keep track of nodes in-use */
	u32 root_count;
	u32 cluster_count;
	u32 leaf_count;
	/* Keep track of assigned SLA's */
	u32 sla_count_root;
	u32 sla_count_cluster;
	u32 sla_count_leaf;
};

/* Structure for slice numbering - generic for all 2.x products */
struct rl_slice_cnt {
	u8 rl_slice_cnt;
	u8 rl_dcpr_slice_cnt;
	u8 rl_pke_slice_cnt;
	u8 rl_cph_slice_cnt;
};

struct rl_scaling_factor {
	u32 pcie_scale_mul;
	u32 pcie_scale_div;
};

struct rl_device_specific {
	u32 ae_freq;
	u32 ae_num;
	u32 scan_interval;
	u32 max_tp[RL_MAX_ROOT];
	u32 slice_ref;
	struct rl_scaling_factor scale_factor;
	struct rl_slice_cnt slice_cnt;
};

/*
 * Internal structure for rl_node_info + rl_node_count
 */
struct adf_rl_v2 {
	struct rl_node_info root_info[RL_MAX_ROOT];
	struct rl_node_count node_count;
	struct rl_device_specific device_specific;
	/* Protects node create/update/delete */
	struct mutex rl_lock;
	struct idr *cluster_idr;
	struct idr *leaf_idr;
};

/*
 * internal struct to track rings associated with an SLA
 */
struct rl_rings_info {
	u32 num_rings;
	u16 rp_ids[RL_MAX_RPS_PER_LEAF];
};

int adf_rl_v2_init(struct adf_accel_dev *accel_dev);
void adf_rl_v2_exit(struct adf_accel_dev *accel_dev);
void rl_v2_get_caps(struct adf_accel_dev *accel_dev,
		    struct adf_user_sla_caps *sla_caps);
void rl_v2_get_user_slas(struct adf_accel_dev *accel_dev,
			 struct adf_user_slas *slas);
int rl_v2_create_user_node(struct adf_accel_dev *accel_dev,
			   struct adf_user_node *node);
int rl_v2_delete_user_node(struct adf_accel_dev *accel_dev,
			   struct adf_user_node *node);
int rl_v2_create_sla(struct adf_accel_dev *accel_dev, struct adf_user_sla *sla);
int rl_v2_update_sla(struct adf_accel_dev *accel_dev, struct adf_user_sla *sla);
int rl_v2_delete_sla(struct adf_accel_dev *accel_dev, struct adf_user_sla *sla);
bool rl_v2_is_svc_enabled(struct adf_accel_dev *accel_dev,
			  enum adf_svc_type adf_svc);
u32 rl_pci_to_vf_num(struct adf_user_sla *sla);
int rl_v2_set_node_id(struct adf_accel_dev *accel_dev,
		      struct adf_user_sla *sla);


#endif /* ADF_GEN4_RL_V2_H_ */
