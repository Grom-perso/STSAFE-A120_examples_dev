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

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include "stse_conf.h"
#include "stselib.h"

#define WC_SHA256_DIGEST_SIZE 32

stse_ReturnCode_t stse_platform_hash_compute(stse_hash_algorithm_t hash_algo,
                                             PLAT_UI8 *pPayload, PLAT_UI16 payload_length,
                                             PLAT_UI8 *pHash, PLAT_UI16 *hash_length) {
#if defined(STSE_CONF_HASH_SHA_1) || defined(STSE_CONF_HASH_SHA_224) ||                                      \
    defined(STSE_CONF_HASH_SHA_256) || defined(STSE_CONF_HASH_SHA_384) || defined(STSE_CONF_HASH_SHA_512) || \
    defined(STSE_CONF_HASH_SHA_3_256) || defined(STSE_CONF_HASH_SHA_3_284) || defined(STSE_CONF_HASH_SHA_3_512)

    int retval = 0;

    switch (hash_algo) {
#ifdef STSE_CONF_HASH_SHA_1
    case STSE_SHA_1:
        if (*hash_length != WC_SHA_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha256Hash(pPayload, payload_length, pHash);
        break;
#endif
#ifdef STSE_CONF_HASH_SHA_224
    case STSE_SHA_224:
        if (*hash_length != WC_SHA224_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha224Hash(pPayload, payload_length, pHash);
        break;
#endif
#ifdef STSE_CONF_HASH_SHA_256
    case STSE_SHA_256:
        if (*hash_length != WC_SHA256_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha256Hash(pPayload, payload_length, pHash);
        break;
#endif
#ifdef STSE_CONF_HASH_SHA_384
    case STSE_SHA_384:
        if (*hash_length != WC_SHA384_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha384Hash(pPayload, payload_length, pHash);
        break;
#endif
#ifdef STSE_CONF_HASH_SHA_512
    case STSE_SHA_512:
        if (*hash_length != WC_SHA512_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha512Hash(pPayload, payload_length, pHash);
        break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_256
    case STSE_SHA3_256:
        if (*hash_length != WC_SHA3_256_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha3_256Hash(pPayload, payload_length, pHash);
        break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_384
    case STSE_SHA3_384:
        if (*hash_length != WC_SHA3_384_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha3_384Hash(pPayload, payload_length, pHash);
        break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_512
    case STSE_SHA3_512:
        if (*hash_length != WC_SHA3_512_DIGEST_SIZE) {
            return STSE_PLATFORM_HASH_ERROR;
        }
        retval = wc_Sha3_512Hash(pPayload, payload_length, pHash);
        break;
#endif
    default:
        return STSE_PLATFORM_HASH_ERROR;
    }

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
    Hmac hmac;
    int retval;

    if (pseudorandom_key_expected_length != WC_SHA256_DIGEST_SIZE) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    /* HKDF Extract: PRK = HMAC-Hash(salt, IKM) */
    retval = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (retval != 0) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    retval = wc_HmacSetKey(&hmac, WC_SHA256, pSalt, salt_length);
    if (retval != 0) {
        wc_HmacFree(&hmac);
        return STSE_PLATFORM_HKDF_ERROR;
    }

    retval = wc_HmacUpdate(&hmac, pInput_keying_material, input_keying_material_length);
    if (retval != 0) {
        wc_HmacFree(&hmac);
        return STSE_PLATFORM_HKDF_ERROR;
    }

    retval = wc_HmacFinal(&hmac, pPseudorandom_key);
    wc_HmacFree(&hmac);

    if (retval != 0) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_hmac_sha256_expand(PLAT_UI8 *pPseudorandom_key, PLAT_UI16 pseudorandom_key_length,
                                                   PLAT_UI8 *pInfo, PLAT_UI16 info_length,
                                                   PLAT_UI8 *pOutput_keying_material, PLAT_UI16 output_keying_material_length) {
    int retval;
    Hmac hmac;
    PLAT_UI8 tmp[WC_SHA256_DIGEST_SIZE];
    PLAT_UI16 tmp_length = 0;
    PLAT_UI16 out_index = 0;
    PLAT_UI8 n = 0x1;

    /*	RFC 5869 : output keying material must be
	 * 		- L <= 255*HashLen
	 * 		- N = ceil(L/HashLen) */
    if (pOutput_keying_material == NULL || ((output_keying_material_length / WC_SHA256_DIGEST_SIZE) + ((output_keying_material_length % WC_SHA256_DIGEST_SIZE) != 0)) > 255) {
        return STSE_PLATFORM_HKDF_ERROR;
    }

    while (out_index < output_keying_material_length) {
        PLAT_UI16 left = output_keying_material_length - out_index;

        retval = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
        if (retval != 0)
            break;

        retval = wc_HmacSetKey(&hmac, WC_SHA256, pPseudorandom_key, pseudorandom_key_length);
        if (retval != 0) {
            wc_HmacFree(&hmac);
            break;
        }

        retval = wc_HmacUpdate(&hmac, tmp, tmp_length);
        if (retval != 0) {
            wc_HmacFree(&hmac);
            break;
        }

        retval = wc_HmacUpdate(&hmac, pInfo, info_length);
        if (retval != 0) {
            wc_HmacFree(&hmac);
            break;
        }

        retval = wc_HmacUpdate(&hmac, &n, 1);
        if (retval != 0) {
            wc_HmacFree(&hmac);
            break;
        }

        retval = wc_HmacFinal(&hmac, tmp);
        wc_HmacFree(&hmac);
        if (retval != 0)
            break;

        left = left < WC_SHA256_DIGEST_SIZE ? left : WC_SHA256_DIGEST_SIZE;
        memcpy(pOutput_keying_material + out_index, tmp, left);

        tmp_length = WC_SHA256_DIGEST_SIZE;
        out_index += WC_SHA256_DIGEST_SIZE;
        n++;
    }

    /*- Verify HMAC compute return */
    if (retval != 0) {
        memset(tmp, 0, WC_SHA256_DIGEST_SIZE);
        memset(pOutput_keying_material, 0, output_keying_material_length);
        return STSE_PLATFORM_HKDF_ERROR;
    }

    return STSE_OK;
}
