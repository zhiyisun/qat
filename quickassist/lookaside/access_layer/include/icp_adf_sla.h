/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *  version: QAT20.L.1.1.50-00003
 *
 ****************************************************************************/
/****************************************************************************
 * @file icp_adf_sla.h
 *
 * @defgroup sla SLA API
 *
 * @description
 *        This is list of ADF SLA APIs. It contains function prototypes
 *        for managing SLAs on Intel(R) QuickAssist Technology.
 *
 ****************************************************************************/
#ifndef ICP_ADF_SLA_H
#define ICP_ADF_SLA_H

/*
 ******************************************************************
 * @ingroup sla
 *        Get SLA capabilities of PF
 *
 * @description
 *        This function is used to get the SLA capabilities of the given
 *        PF device.
 *
 * @param[in]  pPf       Pointer to BDF address of physical function
 * @param[out] pCaps     Pointer to structure that will contains
 *                       SLA capabilities
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invlaid/null arguments
 *
 ******************************************************************
 */
CpaStatus icp_adf_userSlaGetCaps(struct adf_pci_address *pPf,
                                 struct adf_user_sla_caps *pCaps);

/*
 ******************************************************************
 * @ingroup sla
 *        Get the list of SLAs created
 *
 * @description
 *        This function is used to get the list of SLAs created
 *
 * @param[in]  pPf       Pointer to BDF address of physical function
 * @param[out] pSlas     Pointer to structure that will contains
 *                       SLAs list
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invlaid/null arguments
 *
 ******************************************************************
 */
CpaStatus icp_adf_userSlaGetList(struct adf_pci_address *pPf,
                                 struct adf_user_slas *pSlas);

/*
 ******************************************************************
 * @ingroup sla
 *        Create SLA
 *
 * @description
 *        This function is used to create a new SLA for the given VF
 *
 * @param[in]  pSla      Pointer to SLA structure to be created
 * @param[out] pSlaId    Pointer to SLA ID which is created. This id
 *                       can be used to update or delete the SLA entry
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invlaid/null arguments
 *
 * @note SLA's are always rounded up to the nearest K. For example
 *     if the user tries to set sla with rate_in_sla_units=300, the actual
 *     SLA set will be 1000 units. This is because the device cannot
 *     guarantee a finer granularity
 ******************************************************************
 */
CpaStatus icp_adf_userSlaCreateIR(struct adf_user_sla *pSla, Cpa16U *pSlaId);

/*
 ******************************************************************
 * @ingroup sla
 *        Create SLA
 *
 * @description
 *        This function is used to create a new SLA for the given VF
 *
 * @param[in]  pSla      Pointer to SLA structure to be created
 * @param[out] pSlaId    Pointer to SLA ID which is created. This id
 *                       can be used to update or delete the SLA entry
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invlaid/null arguments
 *
 * @note SLA's are always rounded up to the nearest K. For example
 *     if the user tries to set sla with rate_in_sla_units=300, the actual
 *     SLA set will be 1000 units. This is because the device cannot
 *     guarantee a finer granularity
 ******************************************************************
 */
CpaStatus icp_adf_userSlaCreate(struct adf_user_sla *pSla, Cpa16U *pSlaId);

/*
 ******************************************************************
 * @ingroup sla
 *        Update SLA with IR
 *
 * @description
 *        This function is used to update the SLA identified by its ID
 *
 * @param[in] pPf            Pointer to BDF address of physical function
 * @param[in] slaId          SLA ID of the SLA to be updated
 * @param[in] cir            Rate in SLA units, to be assigned to
 *                           the given SLA id
 * @param[in] pir            Peak rate in SLA units, to be assigned to
 *                           the given SLA id
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invlaid/null arguments
 *
 * @note SLA's are always rounded up to the nearest K. For example
 *     if the user tries to set sla with rateInSlaUnits=300, the actual
 *     SLA set will be 1000 units. This is because the device cannot
 *     guarantee a finer granularity
 ******************************************************************
 */
CpaStatus icp_adf_userSlaUpdateIR(struct adf_pci_address *pPf,
                                  Cpa16U pSlaId,
                                  Cpa32U cir,
                                  Cpa32U pir);

/*
 ******************************************************************
 * @ingroup sla
 *        Update SLA
 *
 * @description
 *        This function is used to update the SLA identified by its ID
 *
 * @param[in] pPf            Pointer to BDF address of physical function
 * @param[in] slaId          SLA ID of the SLA to be updated
 * @param[in] rateInSlaUnits Rate in SLA units, to be assigned to
 *                           the given SLA id
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invlaid/null arguments
 *
 * @note SLA's are always rounded up to the nearest K. For example
 *     if the user tries to set sla with rateInSlaUnits=300, the actual
 *     SLA set will be 1000 units. This is because the device cannot
 *     guarantee a finer granularity
 ******************************************************************
 */
CpaStatus icp_adf_userSlaUpdate(struct adf_pci_address *pPf,
                                Cpa16U pSlaId,
                                Cpa32U rateInSlaUnits);

/*
 ******************************************************************
 * @ingroup sla
 *        Delete SLA
 *
 * @description
 *        This function is used to delete the SLA identified by its ID
 *
 * @param[in] pPf        Pointer to BDF address of physical function
 * @param[in] slaId      SLA ID of the SLA to be updated
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invlaid/null arguments
 *
 ******************************************************************
 */
CpaStatus icp_adf_userSlaDelete(struct adf_pci_address *pPf, Cpa16U pSlaId);

#endif
