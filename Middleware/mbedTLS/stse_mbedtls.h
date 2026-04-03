/******************************************************************************
 * \file    stse_mbedtls.h
 * \brief   mbedTLS hardware-acceleration port for STSAFE-A.
 *
 *          This module allows mbedTLS to delegate:
 *           - Entropy collection  → STSAFE True-RNG
 *           - ECDSA-P256 signing  → STSAFE private key stored in a slot
 *
 *          Usage:
 *          @code
 *          mbedtls_entropy_context  ent_ctx;
 *          mbedtls_ctr_drbg_context drbg_ctx;
 *          stse_Handler_t           stse;
 *
 *          // … init stse …
 *
 *          mbedtls_entropy_init(&ent_ctx);
 *          stse_mbedtls_entropy_register(&ent_ctx, &stse);
 *
 *          mbedtls_ctr_drbg_init(&drbg_ctx);
 *          mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func,
 *                                &ent_ctx, NULL, 0);
 *          @endcode
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

#ifndef STSE_MBEDTLS_H
#define STSE_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "stselib.h"

/**
 * @defgroup STSE_mbedTLS mbedTLS Hardware-Acceleration Port
 * @brief    Routes mbedTLS entropy and private-key operations to STSAFE-A.
 * @{
 */

/* --------------------------------------------------------------------------
 * Entropy source
 * -------------------------------------------------------------------------- */

/**
 * @brief  mbedTLS entropy callback backed by the STSAFE True-RNG.
 *
 * This function matches the signature expected by
 * mbedtls_entropy_add_source().  Each call asks the STSAFE device for
 * @p len bytes of hardware-generated entropy.
 *
 * @param[in]  p_ctx   Pointer to the stse_Handler_t passed at registration.
 * @param[out] output  Buffer to fill with entropy bytes.
 * @param[in]  len     Number of entropy bytes requested.
 * @param[out] olen    Actual number of entropy bytes written.
 * @return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on error, 0 on success.
 */
int stse_mbedtls_entropy_poll(void *p_ctx, unsigned char *output,
                               size_t len, size_t *olen);

/**
 * @brief  Register the STSAFE entropy source with an mbedTLS entropy context.
 *
 * Adds stse_mbedtls_entropy_poll() as a strong entropy source backed by the
 * STSAFE True-RNG hardware.
 *
 * @param p_entropy  Initialised mbedtls_entropy_context.
 * @param pSTSE      Initialised STSAFE handler used as entropy source.
 * @return 0 on success, mbedTLS error code on failure.
 */
int stse_mbedtls_entropy_register(mbedtls_entropy_context *p_entropy,
                                   stse_Handler_t          *pSTSE);

/* --------------------------------------------------------------------------
 * Opaque private key
 * -------------------------------------------------------------------------- */

/**
 * @brief  Context structure for a STSAFE-backed mbedTLS private key.
 */
typedef struct {
    stse_Handler_t *pSTSE;     /**< STSAFE device handle           */
    uint8_t         key_slot;  /**< Asymmetric key slot index       */
} stse_mbedtls_pk_ctx_t;

/**
 * @brief  Set up an mbedTLS PK context that uses a STSAFE private key slot.
 *
 * After this call the @p pk context can be used wherever mbedTLS requires a
 * private key (e.g. mbedtls_ssl_conf_own_cert()).  All ECDSA sign operations
 * are transparently offloaded to the STSAFE device; the raw private key never
 * leaves the secure element.
 *
 * @param[out] pk        Uninitialised mbedtls_pk_context to configure.
 * @param[in]  pSTSE     Initialised STSAFE handler.
 * @param[in]  key_slot  STSAFE asymmetric key slot holding the private key.
 * @return 0 on success, MBEDTLS_ERR_PK_ALLOC_FAILED on memory failure.
 */
int stse_mbedtls_pk_setup(mbedtls_pk_context    *pk,
                           stse_Handler_t        *pSTSE,
                           uint8_t                key_slot);

/**
 * @brief  Release resources allocated by stse_mbedtls_pk_setup().
 *
 * @param pk  mbedTLS PK context to release.
 */
void stse_mbedtls_pk_free(mbedtls_pk_context *pk);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* STSE_MBEDTLS_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
