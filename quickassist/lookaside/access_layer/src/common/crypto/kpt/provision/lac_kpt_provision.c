/***************************************************************************
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
/**
 *****************************************************************************
 * @file lac_kpt2_provision.c
 *
 * @ingroup LacKpt
 *
 * This file implements kpt key provision functions.
 *
 *****************************************************************************/
/*
*******************************************************************************
* Include public/global header file
*******************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_kpt.h"
/* Include LAC files */
#include "lac_common.h"
#include "lac_pke_utils.h"
#include "lac_sal_types_crypto.h"
#include "sal_service_state.h"
#include "lac_kpt_pro_qat_comms.h"
/* ADF includes */
#include "icp_adf_cfg.h"


/* Product issue key cert */
static Cpa8U kpt_product_issue_key_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFrDCCBBSgAwIBAgIUShQDHrdYk/549dCw5Yxa/lGj/oEwDQYJKoZIhvcNAQEM\n"
    "BQAwgYsxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEg\n"
    "Q2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSUwIwYDVQQLDBxLUFQg\n"
    "Um9vdCBDZXJ0IFNpZ25pbmcgUlNBIDNLMRYwFAYDVQQDDA13d3cuaW50ZWwuY29t\n"
    "MB4XDTE4MDUwODIwMzY0MVoXDTM1MTIzMTIzNTk1OVowgYQxCzAJBgNVBAYMAlVT\n"
    "MQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUlu\n"
    "dGVsIENvcnBvcmF0aW9uMR4wHAYDVQQLDBVLUFQgSXNzdWluZyBDQSBSU0EgM0sx\n"
    "FjAUBgNVBAMMDXd3dy5pbnRlbC5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw\n"
    "ggGKAoIBgQDJi5vrTU64iwydSGJ/oBSALae9hC1Aa/j1zEbhFqPZcXooN2jOxMBa\n"
    "Py6ZITFTriUJqnHWXrxF6XQN4Wvr3rI242ASW5M41k5hKWvX3dpeyuMwL99Bn75J\n"
    "b2m15IeKzbjwaYS7i5L6+n5z9tw3nBM7rT+hlB+DPlPH7u9QBoupPFU302sumVx0\n"
    "qFobBrOLj5igFsTgZ7zNpRPqzFjIRAxYeXgtQdVu4tsFOZzU1nicKn2vP3/AGNN9\n"
    "yz8pj4bLYNTKB6oeVsGlR7FuAZSyt0QDTDq0R2YE22Gvk/rpjkqn8JERZt/WHjhf\n"
    "g2qA74FVaEx0kawt1uX0Pa51Z9M4n2ifZdpGDhTJLQbLR3AXwjNo7WrvWllRjSqs\n"
    "rQ8vNjB6+lkZPqEeS1mbFAoY4WgUrgcaNTOk5Ik/h2z/CuTPnNDm7wZy11eEJS7Q\n"
    "uujc9wQ67t1gC88pFSscj4Qtk8bM7ekvxTLjsI6J6psY6MrFp0u7/ZDHVolTdaZF\n"
    "mPR3hNMOYw0CAwEAAaOCAQswggEHMB8GA1UdIwQYMBaAFGb6TO43nCxUdtkwRtfx\n"
    "gHsGehDYMB0GA1UdDgQWBBR5Ocgnv1EGEZAUQiBa7nmHPUBi1jAPBgNVHRMBAf8E\n"
    "BTADAQH/MA4GA1UdDwEB/wQEAwIBhjBZBggrBgEFBQcBAQRNMEswSQYIKwYBBQUH\n"
    "MAKGPWh0dHBzOi8vdHNjaS5pbnRlbC5jb20vY29udGVudC9LUFQvY2VydHMvS1BU\n"
    "X1Jvb3RDQV9SU0EzSy5jZXIwSQYDVR0fBEIwQDA+oDygOoY4aHR0cHM6Ly90c2Np\n"
    "LmludGVsLmNvbS9jb250ZW50L0tQVC9jcmxzL0tQVF9DQV9SU0EzSy5jcmwwDQYJ\n"
    "KoZIhvcNAQEMBQADggGBAJ8NAwH/6ftbxI21P1un96qTPngeSiZsahor7h+BPcOD\n"
    "E5NIwsF6T/WSypDl9nyP54CS+/DTThfc9sPj+W46C+bi4N7hVjr3/aRr3HSbfote\n"
    "vOvIdLg7q32FfjPYF59LLzNH5jG0BpDowEGLF6VOOGpz52tzRgnE9+lMT9ryBziN\n"
    "P7qKnGmanmD48U3WE4SDRzugJQI5BrMkG/2S/bbytSz8hAroysPoGJagQ8Gm8vMw\n"
    "2wE8mg2A/YBUyG+XNF5nLWqKpE/CtKl6tH0hma+zgaEjqUrkUzvVsJeZOncR8K6x\n"
    "BfUJCgDxt0veoTJKBmajcnxRGfboS6k0spaigDUjpv/tPA0IbRi33bfTKLxDi0yf\n"
    "1B9Q80zbYNsGk7TQTIpyHmBCMH4C0hEHA8D5Xrc7d8F2ciQWJ70qsL9fWaMiuZF2\n"
    "IU+nj4u8AVodiegU3AKlx1iXqkaoJk5X2scHg2gwx1Zpmq95LOCmbCf6Sei3Ebf4\n"
    "LjUaX5XRu3dWcwaKUcXifQ==\n"
    "-----END CERTIFICATE-----";

/* Product issue key cert */
static Cpa8U kpt_debug_issue_key_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFrDCCBBSgAwIBAgIUQ9DKepJGJw/JT7gF/cRLPQ9AixcwDQYJKoZIhvcNAQEM\n"
    "BQAwgYsxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEg\n"
    "Q2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSUwIwYDVQQLDBxLUFQg\n"
    "Um9vdCBDZXJ0IFNpZ25pbmcgUlNBIDNLMRYwFAYDVQQDDA13d3cuaW50ZWwuY29t\n"
    "MB4XDTE4MDMyNzIyMDIzOVoXDTM1MTIzMTIzNTk1OVowgYQxCzAJBgNVBAYMAlVT\n"
    "MQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUlu\n"
    "dGVsIENvcnBvcmF0aW9uMR4wHAYDVQQLDBVLUFQgSXNzdWluZyBDQSBSU0EgM0sx\n"
    "FjAUBgNVBAMMDXd3dy5pbnRlbC5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw\n"
    "ggGKAoIBgQDDKEjvzCqxgoKtzzpXyuwo/2nRQ6hM16tamsYTBhZ3LtDDElz+BFZY\n"
    "jk9lvdwjUAB+kZ5T43BXiKQ8YI8sg4uRFpw1ybZmZJXAoGBcJVvCF9Gz47ky8nqH\n"
    "ObLxz1C6S4/fmfV65qPRwEe11cIXfoRzkMJ4yhm8b9CTk85yK6WstR67U/qPc9u2\n"
    "1tqFKmaXUCzVnhRdob2VsEHh0pMGE4kdBpyAUBIJQprcEyDNHpqNjfdlvgdW8XBV\n"
    "65lbXWsFf+1nRlLFzqjUvB8Ur7qCJgdXwWFI8rVG6SA0v4w8+SfTg9ECEhrhJZ9N\n"
    "cZiBB8JD3UhzlNKhP/WbRo2H737wibSVS4CDRBUA7EygaqUGI7+SgDEkNnwbw+ql\n"
    "EJB92kwAqUJbAiDkD/rYT+rjasIaOynvLsZiYb2i9bBhBjf2mwmlW3KZwHCKH4TA\n"
    "xUT8Z36ZUHwCH/ZvJydM9tWcqr97gNijA+YLyfaxij8l3AX0DTUHV3j4Iq3oYAHZ\n"
    "TouXivYUAyMCAwEAAaOCAQswggEHMB8GA1UdIwQYMBaAFHbZE5uoByMmdrdZM58A\n"
    "DyPgbXTlMB0GA1UdDgQWBBTGJqNtTohCujN9gOTT5kXQ7QZgXzAPBgNVHRMBAf8E\n"
    "BTADAQH/MA4GA1UdDwEB/wQEAwIBhjBZBggrBgEFBQcBAQRNMEswSQYIKwYBBQUH\n"
    "MAKGPWh0dHBzOi8vdHNjaS5pbnRlbC5jb20vY29udGVudC9LUFQvY2VydHMvS1BU\n"
    "X1Jvb3RDQV9SU0EzSy5jZXIwSQYDVR0fBEIwQDA+oDygOoY4aHR0cHM6Ly90c2Np\n"
    "LmludGVsLmNvbS9jb250ZW50L0tQVC9jcmxzL0tQVF9DQV9SU0EzSy5jcmwwDQYJ\n"
    "KoZIhvcNAQEMBQADggGBADHU9eYYQBD3vTVhfdibq3uDjMqWB6X7miS4nZH3epMI\n"
    "rvT7Q20Fn2JBJGhiUzXcbzC3jFvjEUQ50AH7G+LdTIyUmS2PpAXfNyVXV1E3SOJV\n"
    "0BZORyw2LDlNUXFLZ1XSREoEivPF0UUolLc7fjJ4MwQBILEZGuBg5tLQ0xRkCCHS\n"
    "whwDm0jUD1+7XG6iwFsf1DLfFrfWVM+4ktT/aKmodyMA8PQycb5h5pdrMAxD+pMJ\n"
    "LOQtYK+IZ57+PAaGY+xNirl6GFj5+cW1d5N/xwsMyVDKOI/4J30uK8nubgKGD11M\n"
    "wi9oy9/4xgKXpQBLZ3USHrSdFPh9g3iADEqO6uEseh0xzL/RA1x3K2isXd8MbZEL\n"
    "lx9q5s9NL1+TN9Oqjnb+DnjVoA/8nD096h4n9P/dKjgmBjcA5YDIvN1WXH/abdjf\n"
    "1RyU+9JbzC31/Tv0GJBv7JoxNJAgfHVkED8joQPvnR7kA/D7EruDbYFKi0qOelSh\n"
    "PqZdlpqjaL68VChmecnF2A==\n"
    "-----END CERTIFICATE-----";

#undef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Query kpt issue key certificate parameters check
 ***************************************************************************/
STATIC
CpaStatus LacQueryKptIssueKeyCertParamCheck(
    CpaFlatBuffer *pCert,
    CpaCyKptKeyManagementStatus *pStatus)
{
    LAC_CHECK_NULL_PARAM(pCert);
    LAC_CHECK_NULL_PARAM(pStatus);

    LAC_CHECK_FLAT_BUFFER_PARAM(pCert, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Read hardcoded kpt issue key certificate byte stream
 ***************************************************************************/
STATIC
CpaStatus LacReadKptIssueKeyCert(CpaFlatBuffer *pCert)
{
    if (pCert->dataLenInBytes < MIN(sizeof(kpt_product_issue_key_cert),
                                    sizeof(kpt_debug_issue_key_cert)))
        return CPA_STATUS_INVALID_PARAM;

#ifndef QAT_KPT_DEBUG_KEY
    memcpy(pCert->pData,
           kpt_product_issue_key_cert,
           sizeof(kpt_product_issue_key_cert));
    pCert->dataLenInBytes = sizeof(kpt_product_issue_key_cert);
#else
    memcpy(pCert->pData,
           kpt_debug_issue_key_cert,
           sizeof(kpt_debug_issue_key_cert));
    pCert->dataLenInBytes = sizeof(kpt_debug_issue_key_cert);
#endif

    return CPA_STATUS_SUCCESS;
}

/**
***************************************************************************
* @ingroup LacKptProvision
*      Query kpt issue key certificate from qat driver
***************************************************************************/
CpaStatus cpaCyKptQueryIssuingKeys(const CpaInstanceHandle instanceHandle_in,
                                   CpaFlatBuffer *pPublicX509IssueCert,
                                   CpaCyKptKeyManagementStatus *pKptStatus)
{
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifdef ICP_PARAM_CHECK
    status =
        LacQueryKptIssueKeyCertParamCheck(pPublicX509IssueCert, pKptStatus);
    if (CPA_STATUS_SUCCESS != status)
        return status;
#endif
    instanceHandle = instanceHandle_in;
    *pKptStatus = CPA_CY_KPT_FAILED;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO_ASYM | SAL_SERVICE_TYPE_CRYPTO_SYM));
#endif
    SAL_RUNNING_CHECK(instanceHandle);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (!(pCryptoService->generic_service_info.capabilitiesMask &
          ICP_ACCEL_CAPABILITIES_KPT2))
    {
        return CPA_STATUS_UNSUPPORTED;
    }
    status = LacReadKptIssueKeyCert(pPublicX509IssueCert);
    if (CPA_STATUS_SUCCESS == status)
    {
        *pKptStatus = CPA_CY_KPT_SUCCESS;
    }

    return status;
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Query kpt issue key certificate parameter check
 ***************************************************************************/
STATIC
CpaStatus LacQueryKptDeviceCredentialParamCheck(
    const CpaInstanceHandle instanceHandle,
    CpaCyKptValidationKey *pDevCredential,
    CpaCyKptKeyManagementStatus *pStatus)
{

    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO_ASYM | SAL_SERVICE_TYPE_CRYPTO_SYM));
    SAL_RUNNING_CHECK(instanceHandle);

    LAC_CHECK_NULL_PARAM(pDevCredential);
    LAC_CHECK_NULL_PARAM(pStatus);

    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pDevCredential->publicKey.modulusN), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pDevCredential->publicKey.publicExponentE), CHECK_NONE, 0);

    LAC_CHECK_FLAT_BUFFER_PARAM(&(pDevCredential->publicKey.modulusN),
                                CHECK_GREATER_EQUALS,
                                KPT_DEV_IPUB_N_SIZE_IN_BYTE);

    LAC_CHECK_FLAT_BUFFER_PARAM(&(pDevCredential->publicKey.publicExponentE),
                                CHECK_GREATER_EQUALS,
                                KPT_DEV_IPUB_E_SIZE_IN_BYTE);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
***************************************************************************
* @ingroup LacKptProvision
*      Query kpt device credential from qat device
***************************************************************************/
CpaStatus cpaCyKptQueryDeviceCredentials(
    const CpaInstanceHandle instanceHandle,
    CpaCyKptValidationKey *pDevCredential,
    CpaCyKptKeyManagementStatus *pKptStatus)
{
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifdef ICP_PARAM_CHECK
    status = LacQueryKptDeviceCredentialParamCheck(
        instanceHandle, pDevCredential, pKptStatus);
    if (CPA_STATUS_SUCCESS != status)
        return status;
#endif

    *pKptStatus = CPA_CY_KPT_FAILED;
    if (!(pCryptoService->generic_service_info.capabilitiesMask &
          ICP_ACCEL_CAPABILITIES_KPT2))
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    status = LacKpt_Pro_SendRequest(instanceHandle,
                                    KPT_PRO_QUERY_DEV_CREDENTIAL_CMD,
                                    0,
                                    NULL,
                                    pDevCredential,
                                    pKptStatus);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS != *pKptStatus)
    {
        LAC_LOG_ERROR1("Faild to query device credential, error code: %d \n",
                       *pKptStatus);
    }

    return CPA_STATUS_SUCCESS;
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Kpt load key parameter check
 ***************************************************************************/
STATIC
CpaStatus LacKptLoadKeyParamCheck(const CpaInstanceHandle instanceHandle,
                                  CpaCyKptLoadKey *pSWK,
                                  CpaCyKptHandle *keyHandle,
                                  CpaCyKptKeyManagementStatus *pStatus)
{
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO_ASYM | SAL_SERVICE_TYPE_CRYPTO_SYM));
    SAL_RUNNING_CHECK(instanceHandle);

    LAC_CHECK_NULL_PARAM(pSWK);
    LAC_CHECK_NULL_PARAM(keyHandle);
    LAC_CHECK_NULL_PARAM(pStatus);

    LAC_CHECK_FLAT_BUFFER_PARAM(&(pSWK->eSWK), CHECK_NONE, 0);

    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pSWK->eSWK), CHECK_GREATER_EQUALS, KPT_LOAD_SWK_SIZE_IN_BYTE);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
***************************************************************************
* @ingroup LacKptProvision
*      Kpt load key to qat device
***************************************************************************/
CpaStatus cpaCyKptLoadKey(CpaInstanceHandle instanceHandle,
                          CpaCyKptLoadKey *pSWK,
                          CpaCyKptHandle *keyHandle,
                          CpaCyKptKeyManagementStatus *pKptStatus)
{
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    status =
        LacKptLoadKeyParamCheck(instanceHandle, pSWK, keyHandle, pKptStatus);
    if (CPA_STATUS_SUCCESS != status)
        return status;
#endif

    *pKptStatus = CPA_CY_KPT_FAILED;
    if (!(pCryptoService->generic_service_info.capabilitiesMask &
          ICP_ACCEL_CAPABILITIES_KPT2))
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    status = LacKpt_Pro_SendRequest(instanceHandle,
                                    KPT_PRO_LOAD_SWK_CMD,
                                    keyHandle,
                                    &(pSWK->eSWK),
                                    NULL,
                                    pKptStatus);

    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS != *pKptStatus)
    {

        LAC_LOG_ERROR1("Faild to load key to device, error code: %d \n",
                       *pKptStatus);
    }

    return CPA_STATUS_SUCCESS;
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      kpt delete key parameter check
 ***************************************************************************/
STATIC
CpaStatus LacKptDeleteKeyParamCheck(const CpaInstanceHandle instanceHandle,
                                    CpaCyKptKeyManagementStatus *pStatus)
{
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO_ASYM | SAL_SERVICE_TYPE_CRYPTO_SYM));
    SAL_RUNNING_CHECK(instanceHandle);
    LAC_CHECK_NULL_PARAM(pStatus);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
***************************************************************************
* @ingroup LacKptProvision
*      kpt delete key from qat device
***************************************************************************/
CpaStatus cpaCyKptDeleteKey(CpaInstanceHandle instanceHandle,
                            CpaCyKptHandle keyHandle,
                            CpaCyKptKeyManagementStatus *pKptStatus)
{
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    status = LacKptDeleteKeyParamCheck(instanceHandle, pKptStatus);
    if (CPA_STATUS_SUCCESS != status)
        return status;
#endif

    *pKptStatus = CPA_CY_KPT_FAILED;
    if (!(pCryptoService->generic_service_info.capabilitiesMask &
          ICP_ACCEL_CAPABILITIES_KPT2))
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    status = LacKpt_Pro_SendRequest(instanceHandle,
                                    KPT_PRO_DEL_SWK_CMD,
                                    &keyHandle,
                                    NULL,
                                    NULL,
                                    pKptStatus);

    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS != *pKptStatus)
    {

        LAC_LOG_ERROR1("Faild to delete key from device, error code: %d \n",
                       *pKptStatus);
    }

    return CPA_STATUS_SUCCESS;
}
