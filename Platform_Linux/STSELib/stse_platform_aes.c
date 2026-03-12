/******************************************************************************
 * \file    stse_platform_aes.c
 * \brief   STSecureElement AES platform for Linux (STM32MP1) using OpenSSL
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

#include "stse_conf.h"
#include "stselib.h"
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <string.h>

/* ----------------------------- AES CMAC ----------------------------------- */

#if defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_HOST_SESSION)

static CMAC_CTX *cmac_ctx     = NULL;
static PLAT_UI16 cmac_tag_len = 0;

static const EVP_CIPHER *aes_cmac_cipher(PLAT_UI16 key_length) {
    switch (key_length) {
    case 16:
        return EVP_aes_128_cbc();
    case 24:
        return EVP_aes_192_cbc();
    case 32:
        return EVP_aes_256_cbc();
    default:
        return NULL;
    }
}

stse_ReturnCode_t stse_platform_aes_cmac_init(const PLAT_UI8 *pKey,
                                              PLAT_UI16      key_length,
                                              PLAT_UI16      exp_tag_size) {
    const EVP_CIPHER *cipher = aes_cmac_cipher(key_length);
    if (cipher == NULL) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    if (cmac_ctx != NULL) {
        CMAC_CTX_free(cmac_ctx);
    }

    cmac_ctx = CMAC_CTX_new();
    if (cmac_ctx == NULL) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    if (CMAC_Init(cmac_ctx, pKey, key_length, cipher, NULL) != 1) {
        CMAC_CTX_free(cmac_ctx);
        cmac_ctx = NULL;
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    cmac_tag_len = exp_tag_size;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_append(PLAT_UI8 *pInput, PLAT_UI16 length) {
    if (cmac_ctx == NULL) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    if (CMAC_Update(cmac_ctx, pInput, length) != 1) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute_finish(PLAT_UI8 *pTag, PLAT_UI8 *pTagLen) {
    size_t out_len = (size_t)*pTagLen;

    if (cmac_ctx == NULL) {
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    if (CMAC_Final(cmac_ctx, pTag, &out_len) != 1) {
        CMAC_CTX_free(cmac_ctx);
        cmac_ctx = NULL;
        return STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR;
    }

    CMAC_CTX_free(cmac_ctx);
    cmac_ctx = NULL;
    *pTagLen = (PLAT_UI8)out_len;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify_finish(PLAT_UI8 *pTag) {
    PLAT_UI8 computed_tag[16];
    size_t   out_len = sizeof(computed_tag);

    if (cmac_ctx == NULL) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    if (CMAC_Final(cmac_ctx, computed_tag, &out_len) != 1) {
        CMAC_CTX_free(cmac_ctx);
        cmac_ctx = NULL;
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    CMAC_CTX_free(cmac_ctx);
    cmac_ctx = NULL;

    if (out_len < cmac_tag_len || CRYPTO_memcmp(computed_tag, pTag, cmac_tag_len) != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute(const PLAT_UI8 *pPayload,
                                                 PLAT_UI16       payload_length,
                                                 const PLAT_UI8 *pKey,
                                                 PLAT_UI16       key_length,
                                                 PLAT_UI16       exp_tag_size,
                                                 PLAT_UI8       *pTag,
                                                 PLAT_UI16      *pTag_length) {
    CMAC_CTX        *ctx    = NULL;
    const EVP_CIPHER *cipher = aes_cmac_cipher(key_length);
    size_t            out_len = (size_t)*pTag_length;
    stse_ReturnCode_t ret     = STSE_OK;

    if (cipher == NULL) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    ctx = CMAC_CTX_new();
    if (ctx == NULL) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    if (CMAC_Init(ctx, pKey, key_length, cipher, NULL) != 1 ||
        CMAC_Update(ctx, pPayload, payload_length) != 1 ||
        CMAC_Final(ctx, pTag, &out_len) != 1) {
        ret = STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    } else {
        *pTag_length = (PLAT_UI16)out_len;
        if (out_len < exp_tag_size) {
            ret = STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
        }
    }

    CMAC_CTX_free(ctx);
    return ret;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify(const PLAT_UI8 *pPayload,
                                                PLAT_UI16       payload_length,
                                                const PLAT_UI8 *pKey,
                                                PLAT_UI16       key_length,
                                                const PLAT_UI8 *pTag,
                                                PLAT_UI16       tag_length) {
    PLAT_UI8          computed_tag[16];
    PLAT_UI16         computed_tag_len = sizeof(computed_tag);
    stse_ReturnCode_t ret;

    ret = stse_platform_aes_cmac_compute(pPayload, payload_length,
                                         pKey, key_length,
                                         tag_length, computed_tag, &computed_tag_len);
    if (ret != STSE_OK) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    if (computed_tag_len < tag_length ||
        CRYPTO_memcmp(computed_tag, pTag, tag_length) != 0) {
        return STSE_PLATFORM_AES_CMAC_VERIFY_ERROR;
    }

    return STSE_OK;
}

#endif /* STSE_CONF_USE_HOST_KEY_ESTABLISHMENT || STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT || STSE_CONF_USE_HOST_SESSION */

/* ----------------------------- AES CBC ------------------------------------ */

#if defined(STSE_CONF_USE_HOST_SESSION)

static const EVP_CIPHER *aes_cbc_cipher(PLAT_UI16 key_length) {
    switch (key_length) {
    case 16:
        return EVP_aes_128_cbc();
    case 24:
        return EVP_aes_192_cbc();
    case 32:
        return EVP_aes_256_cbc();
    default:
        return NULL;
    }
}

stse_ReturnCode_t stse_platform_aes_cbc_encrypt(PLAT_UI8 *pPlaintext, PLAT_UI16 plaintext_length,
                                                PLAT_UI8 *pKey, PLAT_UI16 key_length,
                                                PLAT_UI8 *pIv,
                                                PLAT_UI8 *pCiphertext, PLAT_UI16 *pCiphertext_length) {
    EVP_CIPHER_CTX   *ctx    = NULL;
    const EVP_CIPHER *cipher = aes_cbc_cipher(key_length);
    int               out_len, final_len;
    stse_ReturnCode_t ret = STSE_OK;

    if (cipher == NULL) {
        return STSE_PLATFORM_AES_CBC_ENC_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return STSE_PLATFORM_AES_CBC_ENC_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, pKey, pIv) != 1) {
        ret = STSE_PLATFORM_AES_CBC_ENC_ERROR;
        goto cleanup;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0); /* No padding - caller ensures block alignment */

    if (EVP_EncryptUpdate(ctx, pCiphertext, &out_len, pPlaintext, plaintext_length) != 1) {
        ret = STSE_PLATFORM_AES_CBC_ENC_ERROR;
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, pCiphertext + out_len, &final_len) != 1) {
        ret = STSE_PLATFORM_AES_CBC_ENC_ERROR;
        goto cleanup;
    }

    *pCiphertext_length = (PLAT_UI16)(out_len + final_len);

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

stse_ReturnCode_t stse_platform_aes_cbc_decrypt(PLAT_UI8 *pCiphertext, PLAT_UI16 ciphertext_length,
                                                PLAT_UI8 *pKey, PLAT_UI16 key_length,
                                                PLAT_UI8 *pIv,
                                                PLAT_UI8 *pPlaintext, PLAT_UI16 *pPlaintext_length) {
    EVP_CIPHER_CTX   *ctx    = NULL;
    const EVP_CIPHER *cipher = aes_cbc_cipher(key_length);
    int               out_len, final_len;
    stse_ReturnCode_t ret = STSE_OK;

    if (cipher == NULL) {
        return STSE_PLATFORM_AES_CBC_DEC_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return STSE_PLATFORM_AES_CBC_DEC_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, pKey, pIv) != 1) {
        ret = STSE_PLATFORM_AES_CBC_DEC_ERROR;
        goto cleanup;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0); /* No padding */

    if (EVP_DecryptUpdate(ctx, pPlaintext, &out_len, pCiphertext, ciphertext_length) != 1) {
        ret = STSE_PLATFORM_AES_CBC_DEC_ERROR;
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, pPlaintext + out_len, &final_len) != 1) {
        ret = STSE_PLATFORM_AES_CBC_DEC_ERROR;
        goto cleanup;
    }

    *pPlaintext_length = (PLAT_UI16)(out_len + final_len);

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#endif /* STSE_CONF_USE_HOST_SESSION */

/* ----------------------------- AES ECB ------------------------------------ */

#if defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) || \
    defined(STSE_CONF_USE_HOST_SESSION)

static const EVP_CIPHER *aes_ecb_cipher(PLAT_UI16 key_length) {
    switch (key_length) {
    case 16:
        return EVP_aes_128_ecb();
    case 24:
        return EVP_aes_192_ecb();
    case 32:
        return EVP_aes_256_ecb();
    default:
        return NULL;
    }
}

stse_ReturnCode_t stse_platform_aes_ecb_encrypt(PLAT_UI8 *pPlaintext, PLAT_UI16 plaintext_length,
                                                PLAT_UI8 *pKey, PLAT_UI16 key_length,
                                                PLAT_UI8 *pCiphertext, PLAT_UI16 *pCiphertext_length) {
    EVP_CIPHER_CTX   *ctx    = NULL;
    const EVP_CIPHER *cipher = aes_ecb_cipher(key_length);
    int               out_len, final_len;
    stse_ReturnCode_t ret = STSE_OK;

    if (cipher == NULL) {
        return STSE_PLATFORM_AES_ECB_ENC_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return STSE_PLATFORM_AES_ECB_ENC_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, pKey, NULL) != 1) {
        ret = STSE_PLATFORM_AES_ECB_ENC_ERROR;
        goto cleanup;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, pCiphertext, &out_len, pPlaintext, plaintext_length) != 1) {
        ret = STSE_PLATFORM_AES_ECB_ENC_ERROR;
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, pCiphertext + out_len, &final_len) != 1) {
        ret = STSE_PLATFORM_AES_ECB_ENC_ERROR;
        goto cleanup;
    }

    *pCiphertext_length = (PLAT_UI16)(out_len + final_len);

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

stse_ReturnCode_t stse_platform_aes_ecb_decrypt(PLAT_UI8 *pCiphertext, PLAT_UI16 ciphertext_length,
                                                PLAT_UI8 *pKey, PLAT_UI16 key_length,
                                                PLAT_UI8 *pPlaintext, PLAT_UI16 *pPlaintext_length) {
    EVP_CIPHER_CTX   *ctx    = NULL;
    const EVP_CIPHER *cipher = aes_ecb_cipher(key_length);
    int               out_len, final_len;
    stse_ReturnCode_t ret = STSE_OK;

    if (cipher == NULL) {
        return STSE_PLATFORM_AES_ECB_DEC_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return STSE_PLATFORM_AES_ECB_DEC_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, pKey, NULL) != 1) {
        ret = STSE_PLATFORM_AES_ECB_DEC_ERROR;
        goto cleanup;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, pPlaintext, &out_len, pCiphertext, ciphertext_length) != 1) {
        ret = STSE_PLATFORM_AES_ECB_DEC_ERROR;
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, pPlaintext + out_len, &final_len) != 1) {
        ret = STSE_PLATFORM_AES_ECB_DEC_ERROR;
        goto cleanup;
    }

    *pPlaintext_length = (PLAT_UI16)(out_len + final_len);

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#endif /* STSE_CONF_USE_HOST_KEY_ESTABLISHMENT || STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT || STSE_CONF_USE_HOST_SESSION */
