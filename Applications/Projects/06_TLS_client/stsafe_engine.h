/**
 ******************************************************************************
 * @file    stsafe_engine.h
 * @author  CS application team
 * @brief   OpenSSL ENGINE backed by STSAFE-A120 hardware
 *
 * This module exposes a minimal OpenSSL ENGINE that offloads ECDSA private-key
 * operations to the STSAFE-A120 secure element via STSELib.
 *
 * The engine does NOT perform dynamic loading; it is linked directly into the
 * application.  Call stsafe_engine_get() once to obtain (and implicitly
 * register) the engine, then use the returned ENGINE * with the standard
 * OpenSSL SSL_CTX / EVP_PKEY API.
 *
 * Usage outline
 * -------------
 *  1. Initialize the stse_Handler_t for the STSAFE-A120 device.
 *  2. Call stsafe_engine_get() to obtain the ENGINE handle.
 *  3. Call stsafe_engine_load_cert() to read the DER certificate stored in the
 *     STSAFE data zone and decode it as an X509 object.
 *  4. Call stsafe_engine_load_key() to create an EVP_PKEY whose private-key
 *     operations are routed to the STSAFE slot.
 *  5. Pass the X509 and EVP_PKEY to SSL_CTX_use_certificate() /
 *     SSL_CTX_use_PrivateKey().
 *
 ******************************************************************************
 *                      COPYRIGHT 2022 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#ifndef STSAFE_ENGINE_H
#define STSAFE_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

/* OpenSSL headers ---------------------------------------------------------*/
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/x509.h>

/* STSELib headers ---------------------------------------------------------*/
#include "stselib.h"

/* Engine identifiers -------------------------------------------------------*/
#define STSAFE_ENGINE_ID   "stsafe"
#define STSAFE_ENGINE_NAME "STSAFE-A120 Hardware Engine"

/**
 * @brief  Obtain (and register) the STSAFE engine singleton.
 * @return Pointer to the ENGINE, or NULL on failure.
 * @note   Must be called once before any stsafe_engine_load_* function.
 *         The returned pointer is owned by the engine subsystem; do NOT call
 *         ENGINE_free() on it directly.
 */
ENGINE *stsafe_engine_get(void);

/**
 * @brief  Load the device certificate stored in a STSAFE data zone.
 * @param  pSTSE  Pointer to an initialised STSAFE handler.
 * @param  zone   Data zone index holding the DER-encoded leaf certificate.
 * @return Decoded X509 certificate, or NULL on error.
 * @note   The caller is responsible for calling X509_free() on the returned
 *         certificate when it is no longer needed.
 */
X509 *stsafe_engine_load_cert(stse_Handler_t *pSTSE, uint8_t zone);

/**
 * @brief  Create an EVP_PKEY whose ECDSA signing is performed by the STSAFE.
 * @param  e           ENGINE handle (from stsafe_engine_get()).
 * @param  pSTSE       Pointer to an initialised STSAFE handler.
 * @param  slot_number Private key slot inside the STSAFE to use for signing.
 * @param  key_type    ECC key type matching the key in @p slot_number.
 * @param  pub_ec_key  Public EC_KEY extracted from the device certificate.
 *                     Used to set the public portion of the returned key.
 * @return EVP_PKEY wrapping a STSAFE-backed EC_KEY, or NULL on error.
 * @note   The caller is responsible for calling EVP_PKEY_free() on the
 *         returned key when it is no longer needed.
 */
EVP_PKEY *stsafe_engine_load_key(ENGINE           *e,
                                 stse_Handler_t   *pSTSE,
                                 uint8_t           slot_number,
                                 stse_ecc_key_type_t key_type,
                                 EC_KEY           *pub_ec_key);

#ifdef __cplusplus
}
#endif

#endif /* STSAFE_ENGINE_H */
