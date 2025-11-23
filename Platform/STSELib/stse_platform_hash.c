/******************************************************************************
 * \file	stse_platform_hash.c
 * \brief   STSecureElement HASH platform file
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2022 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha3.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "stse_conf.h"
#include "stselib.h"

static mbedtls_md_type_t stse_platform_get_mbedtls_md_type(stse_hash_algorithm_t hash_algo) {
    switch (hash_algo) {
#ifdef STSE_CONF_HASH_SHA_1
    case STSE_SHA_1:
        return MBEDTLS_MD_SHA1;
#endif
#ifdef STSE_CONF_HASH_SHA_224
    case STSE_SHA_224:
        return MBEDTLS_MD_SHA224;
#endif
#ifdef STSE_CONF_HASH_SHA_256
    case STSE_SHA_256:
        return MBEDTLS_MD_SHA256;
#endif
#ifdef STSE_CONF_HASH_SHA_384
    case STSE_SHA_384:
        return MBEDTLS_MD_SHA384;
#endif
#ifdef STSE_CONF_HASH_SHA_512
    case STSE_SHA_512:
        return MBEDTLS_MD_SHA512;
#endif
#ifdef STSE_CONF_HASH_SHA_3_256
    case STSE_SHA3_256:
        return MBEDTLS_MD_SHA3_256;
#endif
#ifdef STSE_CONF_HASH_SHA_3_384
    case STSE_SHA3_384:
        return MBEDTLS_MD_SHA3_384;
#endif
#ifdef STSE_CONF_HASH_SHA_3_512
    case STSE_SHA3_512:
        return MBEDTLS_MD_SHA3_512;
#endif
    default:
        return MBEDTLS_MD_NONE;
    }
}

stse_ReturnCode_t stse_platform_hash_compute(stse_hash_algorithm_t hash_algo,
                                             PLAT_UI8 *pPayload, PLAT_UI16 payload_length,
                                             PLAT_UI8 *pHash, PLAT_UI16 *hash_length) {
#if defined(STSE_CONF_HASH_SHA_1) || defined(STSE_CONF_HASH_SHA_224) ||                                      \
    defined(STSE_CONF_HASH_SHA_256) || defined(STSE_CONF_HASH_SHA_384) || defined(STSE_CONF_HASH_SHA_512) || \
    defined(STSE_CONF_HASH_SHA_3_256) || defined(STSE_CONF_HASH_SHA_3_284) || defined(STSE_CONF_HASH_SHA_3_512)

    int retval;
    mbedtls_md_type_t md_type = stse_platform_get_mbedtls_md_type(hash_algo);
    
    if (md_type == MBEDTLS_MD_NONE) {
        return STSE_PLATFORM_HASH_ERROR;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) {
        return STSE_PLATFORM_HASH_ERROR;
    }

    /* Verify expected hash length matches actual */
    if (*hash_length != mbedtls_md_get_size(md_info)) {
        return STSE_PLATFORM_HASH_ERROR;
    }

    retval = mbedtls_md(md_info, pPayload, payload_length, pHash);

    /*- Verify Hash compute return */
    if (retval != 0) {
        return STSE_PLATFORM_HASH_ERROR;
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_HASH_ERROR;
#endif /* STSE_CONF_HASH_SHA_1 || STSE_CONF_HASH_SHA_224 ||\
          STSE_CONF_HASH_SHA_256 || STSE_CONF_HASH_SHA_384 || STSE_CONF_HASH_SHA_512 ||\
          STSE_CONF_HASH_SHA_3_256 || STSE_CONF_HASH_SHA_3_284 || STSE_CONF_HASH_SHA_3_512 */
}

stse_ReturnCode_t stse_platform_hmac_sha256_extract(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
                                                    PLAT_UI8 *pInput_keying_material, PLAT_UI16 input_keying_material_length,
                                                    PLAT_UI8 *pPseudorandom_key, PLAT_UI16 pseudorandom_key_expected_length) {
    int retval;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    if (md_info == NULL) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    /* HKDF Extract: PRK = HMAC-Hash(salt, IKM) */
    retval = mbedtls_hkdf_extract(md_info,
                                   pSalt,
                                   salt_length,
                                   pInput_keying_material,
                                   input_keying_material_length,
                                   pPseudorandom_key);

    /*- Verify HKDF extract return */
    if (retval != 0) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_hmac_sha256_expand(PLAT_UI8 *pPseudorandom_key, PLAT_UI16 pseudorandom_key_length,
                                                   PLAT_UI8 *pInfo, PLAT_UI16 info_length,
                                                   PLAT_UI8 *pOutput_keying_material, PLAT_UI16 output_keying_material_length) {
    int retval;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    if (md_info == NULL) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    /*	RFC 5869 : output keying material must be
	 * 		- L <= 255*HashLen
	 * 		- N = ceil(L/HashLen) */
    const size_t hash_len = mbedtls_md_get_size(md_info);
    if (pOutput_keying_material == NULL || 
        ((output_keying_material_length / hash_len) + ((output_keying_material_length % hash_len) != 0)) > 255) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    /* HKDF Expand: OKM = HKDF-Expand(PRK, info, L) */
    retval = mbedtls_hkdf_expand(md_info,
                                  pPseudorandom_key,
                                  pseudorandom_key_length,
                                  pInfo,
                                  info_length,
                                  pOutput_keying_material,
                                  output_keying_material_length);

    /*- Verify HKDF expand return */
    if (retval != 0) {
        memset(pOutput_keying_material, 0, output_keying_material_length);
        return STSE_PLATFORM_HKDF_ERROR;
    }

    return STSE_OK;
}
