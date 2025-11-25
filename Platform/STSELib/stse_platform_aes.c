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

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include "stse_conf.h"
#include "stselib.h"

#if defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_HOST_SESSION)

static Cmac cmac_ctx;
static int cmac_initialized = 0;

stse_ReturnCode_t stse_platform_aes_cmac_init(const PLAT_UI8 *pKey,
                                              PLAT_UI16 key_length,
                                              PLAT_UI16 exp_tag_size) {
    int retval;

    (void)exp_tag_size; /* wolfCrypt CMAC always generates full-length tag */

    /* Initialize CMAC context */
    retval = wc_InitCmac(&cmac_ctx, pKey, key_length, WC_CMAC_AES, NULL);
    if (retval != 0) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    cmac_initialized = 1;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_append(PLAT_UI8 *pInput,
                                                PLAT_UI16 lenght) {
    int retval;

    if (!cmac_initialized) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    retval = wc_CmacUpdate(&cmac_ctx, pInput, lenght);
    if (retval != 0) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute_finish(PLAT_UI8 *pTag, PLAT_UI8 *pTagLen) {
    int retval;
    PLAT_UI32 tag_len = *pTagLen;

    if (!cmac_initialized) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    retval = wc_CmacFinal(&cmac_ctx, pTag, &tag_len);
    if (retval != 0) {
        cmac_initialized = 0;
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    *pTagLen = (PLAT_UI8)tag_len;
    cmac_initialized = 0;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify_finish(PLAT_UI8 *pTag) {
    int retval;
    PLAT_UI8 computed_tag[AES_BLOCK_SIZE];
    PLAT_UI32 tag_len = AES_BLOCK_SIZE;

    if (!cmac_initialized) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    retval = wc_CmacFinal(&cmac_ctx, computed_tag, &tag_len);
    cmac_initialized = 0;

    if (retval != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    /* Compare tags using constant-time comparison */
    if (ConstantCompare(computed_tag, pTag, tag_len) != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

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
    PLAT_UI32 tag_len = *pTag_length;

    (void)exp_tag_size; /* wolfCrypt CMAC always generates full-length tag */

    /* Compute CMAC in one shot */
    retval = wc_AesCmacGenerate(pTag, &tag_len, pPayload, payload_length, pKey, key_length);
    if (retval != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    *pTag_length = (PLAT_UI16)tag_len;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify(const PLAT_UI8 *pPayload,
                                                PLAT_UI16 payload_length,
                                                const PLAT_UI8 *pKey,
                                                PLAT_UI16 key_length,
                                                const PLAT_UI8 *pTag,
                                                PLAT_UI16 tag_length) {
    int retval;

    /* Verify CMAC */
    retval = wc_AesCmacVerify(pTag, tag_length, pPayload, payload_length, pKey, key_length);
    if (retval != 0) {
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
    Aes aes;
    int retval;

    /* Initialize AES context for CBC encryption */
    retval = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (retval != 0) {
        return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;
    }

    retval = wc_AesSetKey(&aes, pKey, key_length, pInitial_value, AES_ENCRYPTION);
    if (retval != 0) {
        wc_AesFree(&aes);
        return STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR;
    }

    /* Perform AES CBC encryption */
    retval = wc_AesCbcEncrypt(&aes, pEncryptedtext, pPlaintext, plaintext_length);
    wc_AesFree(&aes);

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
    Aes aes;
    int retval;

    /* Initialize AES context for CBC decryption */
    retval = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (retval != 0) {
        return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;
    }

    retval = wc_AesSetKey(&aes, pKey, key_length, pInitial_value, AES_DECRYPTION);
    if (retval != 0) {
        wc_AesFree(&aes);
        return STSE_PLATFORM_AES_CBC_DECRYPT_ERROR;
    }

    /* Perform AES CBC decryption */
    retval = wc_AesCbcDecrypt(&aes, pPlaintext, pEncryptedtext, encryptedtext_length);
    wc_AesFree(&aes);

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
    Aes aes;
    int retval;
    PLAT_UI16 i;

    /* Initialize AES context for ECB encryption */
    retval = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (retval != 0) {
        return STSE_PLATFORM_AES_ECB_ENCRYPT_ERROR;
    }

    retval = wc_AesSetKey(&aes, pKey, key_length, NULL, AES_ENCRYPTION);
    if (retval != 0) {
        wc_AesFree(&aes);
        return STSE_PLATFORM_AES_ECB_ENCRYPT_ERROR;
    }

    /* Perform AES ECB encryption block by block */
    for (i = 0; i < plaintext_length; i += AES_BLOCK_SIZE) {
        retval = wc_AesEcbEncrypt(&aes, pEncryptedtext + i, pPlaintext + i, AES_BLOCK_SIZE);
        if (retval != 0) {
            wc_AesFree(&aes);
            return STSE_PLATFORM_AES_ECB_ENCRYPT_ERROR;
        }
    }

    wc_AesFree(&aes);
    *pEncryptedtext_length = plaintext_length;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_ecb_dec(const PLAT_UI8 *pEncryptedtext,
                                            PLAT_UI16 encryptedtext_length,
                                            const PLAT_UI8 *pKey,
                                            PLAT_UI16 key_length,
                                            PLAT_UI8 *pPlaintext,
                                            PLAT_UI16 *pPlaintext_length) {
    Aes aes;
    int retval;
    PLAT_UI16 i;

    /* Initialize AES context for ECB decryption */
    retval = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (retval != 0) {
        return STSE_PLATFORM_AES_ECB_DECRYPT_ERROR;
    }

    retval = wc_AesSetKey(&aes, pKey, key_length, NULL, AES_DECRYPTION);
    if (retval != 0) {
        wc_AesFree(&aes);
        return STSE_PLATFORM_AES_ECB_DECRYPT_ERROR;
    }

    /* Perform AES ECB decryption block by block */
    for (i = 0; i < encryptedtext_length; i += AES_BLOCK_SIZE) {
        retval = wc_AesEcbDecrypt(&aes, pPlaintext + i, pEncryptedtext + i, AES_BLOCK_SIZE);
        if (retval != 0) {
            wc_AesFree(&aes);
            return STSE_PLATFORM_AES_ECB_DECRYPT_ERROR;
        }
    }

    wc_AesFree(&aes);
    *pPlaintext_length = encryptedtext_length;

    return STSE_OK;
}
#endif /* defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT)*/
