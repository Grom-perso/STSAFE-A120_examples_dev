/******************************************************************************
 * \file    stse_mbedtls.c
 * \brief   mbedTLS hardware-acceleration port for STSAFE-A implementation.
 *
 *          Provides:
 *           - A hardware entropy source backed by the STSAFE True-RNG.
 *           - An opaque mbedTLS PK context that offloads ECDSA-P256 signing
 *             to the STSAFE private key slot, keeping the raw key material
 *             inside the secure element at all times.
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

#include "stse_mbedtls.h"
#include "mbedtls/error.h"
#include "mbedtls/ecdsa.h"
#include <string.h>
#include <stdlib.h>

/** Size in bytes of one ECDSA-P256 integer component (r or s). */
#define ECDSA_P256_COMPONENT_SIZE 32U

/* --------------------------------------------------------------------------
 * Entropy source
 * -------------------------------------------------------------------------- */

int stse_mbedtls_entropy_poll(void *p_ctx, unsigned char *output,
                               size_t len, size_t *olen)
{
    stse_Handler_t *pSTSE = (stse_Handler_t *)p_ctx;
    stse_ReturnCode_t ret;
    size_t offset = 0;

    if (pSTSE == NULL || output == NULL || olen == NULL) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    *olen = 0;

    /* The STSAFE generate_random command returns 32 bytes per call.
     * Loop to fill the requested buffer. */
    while (offset < len) {
        uint16_t chunk = (uint16_t)((len - offset) > 256U ? 256U
                                                          : (len - offset));
        ret = stse_get_random(pSTSE, chunk,
                              (uint8_t *)(output + offset));
        if (ret != STSE_OK) {
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        offset += chunk;
    }

    *olen = len;
    return 0;
}

int stse_mbedtls_entropy_register(mbedtls_entropy_context *p_entropy,
                                   stse_Handler_t          *pSTSE)
{
    if (p_entropy == NULL || pSTSE == NULL) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    return mbedtls_entropy_add_source(p_entropy,
                                      stse_mbedtls_entropy_poll,
                                      (void *)pSTSE,
                                      32,   /* minimum entropy threshold */
                                      MBEDTLS_ENTROPY_SOURCE_STRONG);
}

/* --------------------------------------------------------------------------
 * Opaque private key – custom mbedTLS PK info
 * -------------------------------------------------------------------------- */

static int stsafe_pk_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_ECDSA || type == MBEDTLS_PK_ECKEY);
}

static size_t stsafe_pk_bitlen(const void *ctx)
{
    (void)ctx;
    return 256; /* NIST-P256 */
}

static int stsafe_pk_sign(void *ctx, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size,
                           size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng)
{
    stse_mbedtls_pk_ctx_t *pk_ctx = (stse_mbedtls_pk_ctx_t *)ctx;
    stse_ReturnCode_t      stse_ret;
    uint8_t                raw_sig[ECDSA_P256_COMPONENT_SIZE * 2U];
    uint16_t               raw_sig_len = sizeof(raw_sig);

    (void)md_alg;
    (void)f_rng;
    (void)p_rng;

    if (pk_ctx == NULL || hash == NULL || sig == NULL || sig_len == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* Sign the pre-computed hash with the STSAFE private key */
    stse_ret = stse_ecc_generate_signature(pk_ctx->pSTSE,
                                           pk_ctx->key_slot,
                                           STSE_ECC_KT_NIST_P_256,
                                           STSE_SHA_256,
                                           hash,
                                           (uint16_t)hash_len,
                                           raw_sig,
                                           &raw_sig_len);
    if (stse_ret != STSE_OK) {
        return MBEDTLS_ERR_PK_HW_ACCEL_FAILED;
    }

    /* DER-encode the raw (r || s) signature */
    uint8_t r_pad = (raw_sig[0]                         & 0x80U) ? 1U : 0U;
    uint8_t s_pad = (raw_sig[ECDSA_P256_COMPONENT_SIZE] & 0x80U) ? 1U : 0U;
    uint8_t r_len = (uint8_t)(ECDSA_P256_COMPONENT_SIZE + r_pad);
    uint8_t s_len = (uint8_t)(ECDSA_P256_COMPONENT_SIZE + s_pad);
    uint8_t seq_len = (uint8_t)(2U + r_len + 2U + s_len);
    size_t  der_len = (size_t)(2U + seq_len);

    if (der_len > sig_size) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    unsigned char *p = sig;
    *p++ = 0x30;
    *p++ = seq_len;
    *p++ = 0x02;
    *p++ = r_len;
    if (r_pad) { *p++ = 0x00; }
    memcpy(p, raw_sig,                          ECDSA_P256_COMPONENT_SIZE);
    p += ECDSA_P256_COMPONENT_SIZE;
    *p++ = 0x02;
    *p++ = s_len;
    if (s_pad) { *p++ = 0x00; }
    memcpy(p, raw_sig + ECDSA_P256_COMPONENT_SIZE, ECDSA_P256_COMPONENT_SIZE);
    p += ECDSA_P256_COMPONENT_SIZE;

    *sig_len = (size_t)(p - sig);
    return 0;
}

static void stsafe_pk_free_ctx(void *ctx)
{
    free(ctx);
}

static const mbedtls_pk_info_t stsafe_pk_info = {
    .type        = MBEDTLS_PK_OPAQUE,
    .name        = "STSAFE-A",
    .get_bitlen  = stsafe_pk_bitlen,
    .can_do      = stsafe_pk_can_do,
    .verify_func = NULL,
    .sign_func   = stsafe_pk_sign,
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = NULL,
    .ctx_alloc_func  = NULL,
    .ctx_free_func   = stsafe_pk_free_ctx,
    .debug_func      = NULL,
};

int stse_mbedtls_pk_setup(mbedtls_pk_context *pk,
                           stse_Handler_t     *pSTSE,
                           uint8_t             key_slot)
{
    stse_mbedtls_pk_ctx_t *ctx;

    if (pk == NULL || pSTSE == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    ctx = (stse_mbedtls_pk_ctx_t *)malloc(sizeof(stse_mbedtls_pk_ctx_t));
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ctx->pSTSE    = pSTSE;
    ctx->key_slot = key_slot;

    mbedtls_pk_init(pk);
    pk->pk_info = &stsafe_pk_info;
    pk->pk_ctx  = ctx;

    return 0;
}

void stse_mbedtls_pk_free(mbedtls_pk_context *pk)
{
    if (pk == NULL) {
        return;
    }
    if (pk->pk_ctx != NULL) {
        free(pk->pk_ctx);
        pk->pk_ctx = NULL;
    }
    pk->pk_info = NULL;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
