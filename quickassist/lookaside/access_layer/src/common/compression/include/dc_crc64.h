/****************************************************************************
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
 *  version: QAT20.L.1.1.50-00003
 *
 ***************************************************************************/

#ifndef DC_CRC64_H_
#define DC_CRC64_H_

#include <cpa_types.h>
#include <cpa_dc.h>
#include "lac_common.h"
#include "dc_session.h"

/**
 * @description
 *     Calculates CRC-64 ECMA-182 checksum for given buffer
 *
 * @param[in]  initial_crc    Initial CRC-64 value (used for multi-segment calc)
 * @param[in]  buffer         Pointer to data byte array to calculate CRC on
 * @param[in]  buffer_length  Length of data array
 *
 * @retval Cpa64U             64bit long CRC checksum for given buffer
 */
extern Cpa64U crc64_ecma_norm_by8(Cpa64U initial_crc,
                                  const Cpa8U *buffer,
                                  Cpa64U buffer_length);

/**
 * @description
 *     Helper function to calculate CRC64 checksum on a buffer list.
 *
 *     For a given SGL, the CRC64 checksum is calculated based on the
 *     size of the buffer list.
 *
 * @param[out] checksum       New CRC64 checksum value
 * @param[in]  pBufferList    virtual address of src SGL to calculate CRC on.
 * @param[in]  consumedBytes  total number of bytes inside of pUserSrcBuff
 *                            to calculate CRC checksum for.
 * @param[in]  seedChecksum   Input checksum from where the calculation
 *                            will start from.
 * @note
 *     currently only CRC-64 ECMA-182 (0x42f0E1EBA9EA3693) algorithm
 *     is supported for calculating CRCs on input and output buffers
 *     and CRC value is expected to be 64bit long.
 */
Cpa64U dcCalculateCrc64(const CpaBufferList *pBufferList,
                        Cpa32U consumedBytes,
                        Cpa64U seedChecksum);

/**
 * @description
 *     Creates a lookup table for CRC64 calculation
 *
 *     Function creates a lookup table for a given polynomial. This table is
 *     used to speed up CRC64 calculation at runtime.
 *
 * @param[in]  crc64Polynomial  CRC64 polynomial used for generating the crc
 *                              look up table.
 * @param[out] pCrcLookupTable  Address of pointer to the crc look up table
 *                              created.
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 * @retval CPA_STATUS_RESOURCE  Memory allocation error
 *
 */
CpaStatus dcGenerateLookupTable(Cpa64U crc64Polynomial,
                                Cpa64U **pCrcLookupTable);

/**
 * @description
 *     Calculates programmable CRC-64 checksum for given Buffer List
 *
 *     Function loops through all of the flat buffers in the buffer list.
 *     CRC is calculated for each flat buffer, but output CRC from
 *     buffer[0] is used as input seed for buffer[1] CRC calculation
 *     (and so on until looped through all flat buffers).
 *     Resulting CRC is final CRC for all buffers in the buffer list struct
 *
 * @param[in]  pCrcConfig           Pointer to the crc configuration used for
 *                                  calculating the checksum.
 * @param[in]  pCrcLookupTable      Pointer to the crc look up table used for
 *                                  calculating the checksum.
 * @param[in]  bufferList           Pointer to data byte array to calculate CRC
 *                                  on.
 * @param[in]  consumedBytes        Total number of bytes to calculate CRC on
 *                                  (for all buffer in buffer list)
 * @param[out] pSwCrc               Pointer to 64bit long CRC checksum for the
 *                                  given buffer list.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in
 */
CpaStatus dcCalculateProgCrc64(const CpaCrcControlData *pCrcConfig,
                               Cpa64U *pCrcLookupTable,
                               const CpaBufferList *pBufferList,
                               Cpa32U consumedBytes,
                               Cpa64U *pSwCrc);

#endif /* end of DC_CRC64_H_ */