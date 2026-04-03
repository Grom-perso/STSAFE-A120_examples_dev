/******************************************************************************
 * \file    stse_matter.h
 * \brief   STSecureElement Matter Attestation Plugin API.
 *
 *          This module provides the high-level functions required to integrate
 *          a STSAFE-A110/A120 secure element with the Connectivity Standards
 *          Alliance (CSA) Matter SDK (project-chip).
 *
 *          The STSAFE device stores:
 *           - The Device Attestation Certificate (DAC) in a dedicated data
 *             zone (default: STSE_MATTER_DAC_ZONE).
 *           - The Product Attestation Intermediate (PAI) certificate in an
 *             adjacent zone (default: STSE_MATTER_PAI_ZONE).
 *           - The DAC private key in a static asymmetric key slot
 *             (default: STSE_MATTER_DAC_KEY_SLOT).
 *
 *          These defaults can be overridden by defining the macros before
 *          including this header.
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

#ifndef STSE_MATTER_H
#define STSE_MATTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stselib.h"

/**
 * @defgroup STSE_Matter Matter Attestation Plugin
 * @brief    High-level Matter Device Attestation APIs for STSAFE-A.
 * @{
 */

/** Data zone that holds the Device Attestation Certificate (DER-encoded). */
#ifndef STSE_MATTER_DAC_ZONE
#define STSE_MATTER_DAC_ZONE  0U
#endif

/** Data zone that holds the PAI certificate (DER-encoded). */
#ifndef STSE_MATTER_PAI_ZONE
#define STSE_MATTER_PAI_ZONE  1U
#endif

/** Static asymmetric key slot that holds the DAC private key (NIST-P256). */
#ifndef STSE_MATTER_DAC_KEY_SLOT
#define STSE_MATTER_DAC_KEY_SLOT 0U
#endif

/** Maximum DER certificate size supported by this implementation. */
#define STSE_MATTER_MAX_CERT_SIZE   1024U

/**
 * @brief  Maximum attestation signature size.
 *         ECDSA-P256 produces two 32-byte integers encoded in DER (≤72 B).
 */
#define STSE_MATTER_MAX_SIG_SIZE    72U

/**
 * @brief  Retrieve the DAC certificate chain from the STSAFE device.
 *
 * Reads the Device Attestation Certificate (DAC) and the Product Attestation
 * Intermediate (PAI) certificate from the STSAFE data partition zones.
 * Both certificates are returned in DER (binary) encoding.
 *
 * @param[in]  pSTSE       Pointer to an initialised stse_Handler_t.
 * @param[out] pDac        Buffer to receive the DAC (DER).
 * @param[in,out] pDacLen  In: capacity of pDac. Out: actual DAC length.
 * @param[out] pPai        Buffer to receive the PAI (DER).
 * @param[in,out] pPaiLen  In: capacity of pPai. Out: actual PAI length.
 *
 * @return STSE_OK on success, or an stse_ReturnCode_t error code.
 */
stse_ReturnCode_t stse_matter_get_dac_chain(stse_Handler_t *pSTSE,
                                            uint8_t        *pDac,
                                            uint16_t       *pDacLen,
                                            uint8_t        *pPai,
                                            uint16_t       *pPaiLen);

/**
 * @brief  Sign an attestation message using the STSAFE DAC private key.
 *
 * Computes the SHA-256 digest of the message formed by concatenating the
 * attestation @p pNonce with an internal attestation element TBS buffer,
 * then signs the digest using the STSAFE ECDSA private key stored in slot
 * STSE_MATTER_DAC_KEY_SLOT.
 *
 * The resulting signature is DER-encoded ECDSA (r, s) as expected by the
 * Matter SDK AttestationVerificationProvider interface.
 *
 * @param[in]  pSTSE         Pointer to an initialised stse_Handler_t.
 * @param[in]  pMessage      Message bytes to sign (attestation TBS data).
 * @param[in]  messageLen    Length of pMessage in bytes.
 * @param[out] pSignature    Buffer to receive the DER-encoded signature.
 * @param[in,out] pSigLen    In: capacity of pSignature.
 *                           Out: actual DER signature length (≤72 bytes).
 *
 * @return STSE_OK on success, or an stse_ReturnCode_t error code.
 */
stse_ReturnCode_t stse_matter_sign_attestation(stse_Handler_t *pSTSE,
                                               const uint8_t  *pMessage,
                                               uint16_t        messageLen,
                                               uint8_t        *pSignature,
                                               uint16_t       *pSigLen);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* STSE_MATTER_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
