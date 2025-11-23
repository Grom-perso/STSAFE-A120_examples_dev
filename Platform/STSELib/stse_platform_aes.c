/******************************************************************************
 * \file	stse_platform_crypto.c
 * \brief   STSecureElement cryptographic platform file
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

#include "mbedtls/cmac.h"
#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"
#include "mbedtls/nist_kw.h"
#include "stse_conf.h"
#include "stselib.h"

mbedtls_cipher_context_t CMAC_Handler;

#if defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_HOST_SESSION)

stse_ReturnCode_t stse_platform_aes_cmac_init(const PLAT_UI8 *pKey,
                                              PLAT_UI16 key_length,
                                              PLAT_UI16 exp_tag_size) {
    int retval;
    const mbedtls_cipher_info_t *cipher_info;

    /* Initialize cipher context */
    mbedtls_cipher_init(&CMAC_Handler);

    /* Get cipher info for AES */
    if (key_length == 16) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    } else if (key_length == 24) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
    } else if (key_length == 32) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
    } else {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    if (cipher_info == NULL) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    /* Setup cipher */
    retval = mbedtls_cipher_setup(&CMAC_Handler, cipher_info);
    if (retval != 0) {
        mbedtls_cipher_free(&CMAC_Handler);
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    /* Set CMAC key */
    retval = mbedtls_cipher_cmac_starts(&CMAC_Handler, pKey, key_length * 8);
    if (retval != 0) {
        mbedtls_cipher_free(&CMAC_Handler);
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_append(PLAT_UI8 *pInput,
                                                PLAT_UI16 lenght) {
    int retval;

    retval = mbedtls_cipher_cmac_update(&CMAC_Handler, pInput, lenght);

    if (retval != 0) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute_finish(PLAT_UI8 *pTag, PLAT_UI8 *pTagLen) {
    int retval;
    PLAT_UI8 full_tag[16];  /* AES-CMAC produces 16-byte tag */

    retval = mbedtls_cipher_cmac_finish(&CMAC_Handler, full_tag);
    if (retval != 0) {
        mbedtls_cipher_free(&CMAC_Handler);
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    /* Copy only the requested tag length */
    memcpy(pTag, full_tag, *pTagLen);

    mbedtls_cipher_free(&CMAC_Handler);

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify_finish(PLAT_UI8 *pTag) {
    int retval;
    PLAT_UI8 computed_tag[16];  /* AES-CMAC produces 16-byte tag */

    retval = mbedtls_cipher_cmac_finish(&CMAC_Handler, computed_tag);
    if (retval != 0) {
        mbedtls_cipher_free(&CMAC_Handler);
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    /* Compare tags - note: we need to know expected tag length */
    /* For now, compare full 16 bytes */
    if (memcmp(computed_tag, pTag, 16) != 0) {
        mbedtls_cipher_free(&CMAC_Handler);
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    mbedtls_cipher_free(&CMAC_Handler);

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute(const PLAT_UI8 *pPayload,
                                                 PLAT_UI16 payload_length,
                                                 const PLAT_UI8 *pKey,
                                                 PLAT_UI16 key_length,
                                                 PLAT_UI16 exp_tag_size,
                                                 PLAT_UI8 *pTag,
                                                 PLAT_UI16 *pTag_length) {
    int retval;
    const mbedtls_cipher_info_t *cipher_info;
    PLAT_UI8 full_tag[16];  /* AES-CMAC produces 16-byte tag */

    /* Get cipher info based on key length */
    if (key_length == 16) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    } else if (key_length == 24) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
    } else if (key_length == 32) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
    } else {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    if (cipher_info == NULL) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    /* Compute CMAC */
    retval = mbedtls_cipher_cmac(cipher_info,
                                 pKey,
                                 key_length * 8,
                                 pPayload,
                                 payload_length,
                                 full_tag);

    if (retval != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    /* Copy requested tag length */
    memcpy(pTag, full_tag, exp_tag_size);
    *pTag_length = exp_tag_size;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify(const PLAT_UI8 *pPayload,
                                                PLAT_UI16 payload_length,
                                                const PLAT_UI8 *pKey,
                                                PLAT_UI16 key_length,
                                                const PLAT_UI8 *pTag,
                                                PLAT_UI16 tag_length) {
    int retval;
    const mbedtls_cipher_info_t *cipher_info;
    PLAT_UI8 computed_tag[16];  /* AES-CMAC produces 16-byte tag */

    /* Get cipher info based on key length */
    if (key_length == 16) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    } else if (key_length == 24) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
    } else if (key_length == 32) {
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
    } else {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    if (cipher_info == NULL) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    /* Compute CMAC */
    retval = mbedtls_cipher_cmac(cipher_info,
                                 pKey,
                                 key_length * 8,
                                 pPayload,
                                 payload_length,
                                 computed_tag);

    if (retval != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    /* Compare tags */
    if (memcmp(computed_tag, pTag, tag_length) != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    return STSE_OK;
}
#endif /* defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) */

#if defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_HOST_SESSION)
stse_ReturnCode_t stse_platform_aes_cbc_enc(const PLAT_UI8 *pPlaintext,
                                            PLAT_UI16 plaintext_length,
                                            PLAT_UI8 *pInitial_value,
                                            const PLAT_UI8 *pKey,
                                            PLAT_UI16 key_length,
                                            PLAT_UI8 *pEncryptedtext,
                                            PLAT_UI16 *pEncryptedtext_length) {
    int retval;
    mbedtls_aes_context aes_ctx;
    PLAT_UI8 iv_copy[16];

    /* Copy IV since mbedtls_aes_crypt_cbc modifies it */
    memcpy(iv_copy, pInitial_value, 16);

    mbedtls_aes_init(&aes_ctx);

    /* Set encryption key */
    retval = mbedtls_aes_setkey_enc(&aes_ctx, pKey, key_length * 8);
    if (retval != 0) {
        mbedtls_aes_free(&aes_ctx);
        return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;
    }

    /* Perform AES CBC encryption */
    retval = mbedtls_aes_crypt_cbc(&aes_ctx,
                                   MBEDTLS_AES_ENCRYPT,
                                   plaintext_length,
                                   iv_copy,
                                   pPlaintext,
                                   pEncryptedtext);

    mbedtls_aes_free(&aes_ctx);

    if (retval != 0) {
        return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;
    }

    *pEncryptedtext_length = plaintext_length;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cbc_dec(const PLAT_UI8 *pEncryptedtext,
                                            PLAT_UI16 encryptedtext_length,
                                            PLAT_UI8 *pInitial_value,
                                            const PLAT_UI8 *pKey,
                                            PLAT_UI16 key_length,
                                            PLAT_UI8 *pPlaintext,
                                            PLAT_UI16 *pPlaintext_length) {
    int retval;
    mbedtls_aes_context aes_ctx;
    PLAT_UI8 iv_copy[16];

    /* Copy IV since mbedtls_aes_crypt_cbc modifies it */
    memcpy(iv_copy, pInitial_value, 16);

    mbedtls_aes_init(&aes_ctx);

    /* Set decryption key */
    retval = mbedtls_aes_setkey_dec(&aes_ctx, pKey, key_length * 8);
    if (retval != 0) {
        mbedtls_aes_free(&aes_ctx);
        return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;
    }

    /* Perform AES CBC decryption */
    retval = mbedtls_aes_crypt_cbc(&aes_ctx,
                                   MBEDTLS_AES_DECRYPT,
                                   encryptedtext_length,
                                   iv_copy,
                                   pEncryptedtext,
                                   pPlaintext);

    mbedtls_aes_free(&aes_ctx);

    if (retval != 0) {
        return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;
    }

    *pPlaintext_length = encryptedtext_length;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_ecb_enc(const PLAT_UI8 *pPlaintext,
                                            PLAT_UI16 plaintext_length,
                                            const PLAT_UI8 *pKey,
                                            PLAT_UI16 key_length,
                                            PLAT_UI8 *pEncryptedtext,
                                            PLAT_UI16 *pEncryptedtext_length) {
    int retval;
    mbedtls_aes_context aes_ctx;
    PLAT_UI16 i;

    mbedtls_aes_init(&aes_ctx);

    /* Set encryption key */
    retval = mbedtls_aes_setkey_enc(&aes_ctx, pKey, key_length * 8);
    if (retval != 0) {
        mbedtls_aes_free(&aes_ctx);
        return STSE_PLATFORM_AES_ECB_ENCRYPT_ERROR;
    }

    /* Perform AES ECB encryption block by block (16 bytes at a time) */
    for (i = 0; i < plaintext_length; i += 16) {
        retval = mbedtls_aes_crypt_ecb(&aes_ctx,
                                       MBEDTLS_AES_ENCRYPT,
                                       pPlaintext + i,
                                       pEncryptedtext + i);
        if (retval != 0) {
            mbedtls_aes_free(&aes_ctx);
            return STSE_PLATFORM_AES_ECB_ENCRYPT_ERROR;
        }
    }

    mbedtls_aes_free(&aes_ctx);

    *pEncryptedtext_length = plaintext_length;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_ecb_dec(const PLAT_UI8 *pEncryptedtext,
                                            PLAT_UI16 encryptedtext_length,
                                            const PLAT_UI8 *pKey,
                                            PLAT_UI16 key_length,
                                            PLAT_UI8 *pPlaintext,
                                            PLAT_UI16 *pPlaintext_length) {
    int retval;
    mbedtls_aes_context aes_ctx;
    PLAT_UI16 i;

    mbedtls_aes_init(&aes_ctx);

    /* Set decryption key */
    retval = mbedtls_aes_setkey_dec(&aes_ctx, pKey, key_length * 8);
    if (retval != 0) {
        mbedtls_aes_free(&aes_ctx);
        return STSE_PLATFORM_AES_ECB_DECRYPT_ERROR;
    }

    /* Perform AES ECB decryption block by block (16 bytes at a time) */
    for (i = 0; i < encryptedtext_length; i += 16) {
        retval = mbedtls_aes_crypt_ecb(&aes_ctx,
                                       MBEDTLS_AES_DECRYPT,
                                       pEncryptedtext + i,
                                       pPlaintext + i);
        if (retval != 0) {
            mbedtls_aes_free(&aes_ctx);
            return STSE_PLATFORM_AES_ECB_DECRYPT_ERROR;
        }
    }

    mbedtls_aes_free(&aes_ctx);

    *pPlaintext_length = encryptedtext_length;

    return STSE_OK;
}
#endif /* defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT)*/
