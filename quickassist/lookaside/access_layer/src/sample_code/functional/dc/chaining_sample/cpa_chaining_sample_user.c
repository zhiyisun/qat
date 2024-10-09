/******************************************************************************
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
 *****************************************************************************/

/**
 ******************************************************************************
 * @file  cpa_chaining_sample_user.c
 * argv[1], 1 = Enable 0 = Disable -> gDebugParam
 * argv[2], 1 = Enable 0 = Disable -> useHardCodedCrc
 * By defult gDebugParam and useHardCodedCrc are eanbled
 * Example to run, ./chaining_sample 1 0
 *****************************************************************************/
#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_dc.h"
#include "cpa_dc_chain.h"
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

int gDebugParam = 1;
int useHardCodedCrc = 1;

#ifdef SC_CHAINING_EXT_ENABLED
extern CpaStatus dcChainXstorSample(void);
#endif
extern CpaStatus dcChainSample(void);

int main(int argc, const char **argv)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;

    if (argc > 1 && argc < 4)
    {
        if (argc == 2)
        {
            gDebugParam = atoi(argv[1]);
        }
        else if (argc == 3)
        {
            gDebugParam = atoi(argv[1]);
            useHardCodedCrc = atoi(argv[2]);
        }
    }

    PRINT_DBG("Starting Chaining Sample Code App ...\n");

    stat = qaeMemInit();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to initialize memory driver\n");
        return (int)stat;
    }

    stat = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to start user process SSL\n");
        qaeMemDestroy();
        return (int)stat;
    }

    /* Legacy DC Chaining Sample Code */
    stat = dcChainSample();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("\nLegacy DC Chaining Sample Code App failed\n");
    }
    else
    {
        PRINT_DBG("\nLegacy DC Chaining Sample Code App finished\n");
    }

#ifdef SC_CHAINING_EXT_ENABLED
    /* Xstor DC Chaining Sample Code */
    stat = dcChainXstorSample();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("\nXstor DC Chaining Sample Code App failed\n");
    }
    else
    {
        PRINT_DBG("\nXstor DC Chaining Sample Code App finished\n");
    }
#endif

    icp_sal_userStop();

    qaeMemDestroy();

    return (int)stat;
}