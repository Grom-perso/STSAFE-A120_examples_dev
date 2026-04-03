/******************************************************************************
 * \file    stse_matter.c
 * \brief   STSecureElement Matter Attestation Plugin implementation.
 *
 *          Implements stse_matter_get_dac_chain() and
 *          stse_matter_sign_attestation() on top of the STSELib public API.
 *
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2024 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include "stse_matter.h"
#include <string.h>

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Read a DER certificate from a STSAFE data zone.
 *
 * The certificate is expected to start with the DER TLV SEQUENCE tag (0x30).
 * Its total length is derived from the DER length field so that the caller
 * does not need to know the exact size in advance.
 *
 * Zones are read using stse_data_storage_read_data_zone() which is part of
 * the public STSELib API.
 *
 * @param pSTSE      Initialised STSAFE handler.
 * @param zone       Data zone index.
 * @param pCert      Output buffer.
 * @param pCertLen   In: buffer capacity; Out: actual certificate length.
 * @return STSE_OK on success.
 */
static stse_ReturnCode_t read_cert_from_zone(stse_Handler_t *pSTSE,
                                             uint8_t         zone,
                                             uint8_t        *pCert,
                                             uint16_t       *pCertLen)
{
    stse_ReturnCode_t ret;
    uint8_t  hdr[4];  /* enough to decode DER length */
    uint16_t cert_len;

    if (pSTSE == NULL || pCert == NULL || pCertLen == NULL) {
        return STSE_API_INVALID_PARAMETER;
    }

    /* Read the first 4 bytes to determine the DER-encoded total length */
    ret = stse_data_storage_read_data_zone(pSTSE, zone, 0, hdr, sizeof(hdr), 0);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Verify DER SEQUENCE tag */
    if (hdr[0] != 0x30) {
        return STSE_API_INVALID_PARAMETER;
    }

    /* Decode DER length */
    if (hdr[1] & 0x80U) {
        /* Multi-byte length */
        uint8_t num_bytes = hdr[1] & 0x7FU;
        if (num_bytes == 1U) {
            cert_len = (uint16_t)hdr[2] + 2U + 1U; /* tag + 1-len-byte + value */
        } else if (num_bytes == 2U) {
            cert_len = (uint16_t)(((uint16_t)hdr[2] << 8) | hdr[3]) + 2U + 2U;
        } else {
            return STSE_API_INVALID_PARAMETER;
        }
    } else {
        cert_len = (uint16_t)hdr[1] + 2U;  /* tag + 1-byte-len + value */
    }

    if (cert_len > *pCertLen) {
        return STSE_API_INVALID_PARAMETER;
    }

    /* Read the full certificate */
    ret = stse_data_storage_read_data_zone(pSTSE, zone, 0,
                                           pCert, cert_len, 0);
    if (ret == STSE_OK) {
        *pCertLen = cert_len;
    }

    return ret;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

stse_ReturnCode_t stse_matter_get_dac_chain(stse_Handler_t *pSTSE,
                                            uint8_t        *pDac,
                                            uint16_t       *pDacLen,
                                            uint8_t        *pPai,
                                            uint16_t       *pPaiLen)
{
    stse_ReturnCode_t ret;

    if (pSTSE == NULL ||
        pDac == NULL || pDacLen == NULL ||
        pPai == NULL || pPaiLen == NULL) {
        return STSE_API_INVALID_PARAMETER;
    }

    /* Read Device Attestation Certificate */
    ret = read_cert_from_zone(pSTSE, STSE_MATTER_DAC_ZONE, pDac, pDacLen);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Read Product Attestation Intermediate certificate */
    ret = read_cert_from_zone(pSTSE, STSE_MATTER_PAI_ZONE, pPai, pPaiLen);

    return ret;
}

stse_ReturnCode_t stse_matter_sign_attestation(stse_Handler_t *pSTSE,
                                               const uint8_t  *pMessage,
                                               uint16_t        messageLen,
                                               uint8_t        *pSignature,
                                               uint16_t       *pSigLen)
{
    stse_ReturnCode_t ret;
    /* ECDSA-P256 raw signature: r (32 B) + s (32 B) */
    uint8_t  raw_sig[64];
    uint16_t raw_sig_len = sizeof(raw_sig);

    if (pSTSE == NULL ||
        pMessage == NULL || messageLen == 0U ||
        pSignature == NULL || pSigLen == NULL) {
        return STSE_API_INVALID_PARAMETER;
    }

    if (*pSigLen < STSE_MATTER_MAX_SIG_SIZE) {
        return STSE_API_INVALID_PARAMETER;
    }

    /* Sign the message with the DAC private key stored in the STSAFE */
    ret = stse_ecc_generate_signature(pSTSE,
                                      STSE_MATTER_DAC_KEY_SLOT,
                                      STSE_ECC_KT_NIST_P_256,
                                      STSE_SHA_256,
                                      pMessage,
                                      messageLen,
                                      raw_sig,
                                      &raw_sig_len);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Encode the raw (r, s) as a DER SEQUENCE { INTEGER r, INTEGER s } */
    uint8_t  r[32], s[32];
    uint8_t  r_pad, s_pad;

    memcpy(r, raw_sig,        32);
    memcpy(s, raw_sig + 32,   32);

    /* DER INTEGER requires a leading 0x00 if the MSBit is set */
    r_pad = (r[0] & 0x80U) ? 1U : 0U;
    s_pad = (s[0] & 0x80U) ? 1U : 0U;

    uint8_t r_len  = (uint8_t)(32U + r_pad);
    uint8_t s_len  = (uint8_t)(32U + s_pad);
    uint8_t seq_content_len = (uint8_t)(2U + r_len + 2U + s_len);
    uint8_t der_total_len   = (uint8_t)(2U + seq_content_len);

    if (der_total_len > *pSigLen) {
        return STSE_API_INVALID_PARAMETER;
    }

    uint8_t *p = pSignature;
    *p++ = 0x30;               /* SEQUENCE */
    *p++ = seq_content_len;
    *p++ = 0x02;               /* INTEGER r */
    *p++ = r_len;
    if (r_pad) { *p++ = 0x00; }
    memcpy(p, r, 32); p += 32;
    *p++ = 0x02;               /* INTEGER s */
    *p++ = s_len;
    if (s_pad) { *p++ = 0x00; }
    memcpy(p, s, 32); p += 32;

    *pSigLen = (uint16_t)(p - pSignature);

    return STSE_OK;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
