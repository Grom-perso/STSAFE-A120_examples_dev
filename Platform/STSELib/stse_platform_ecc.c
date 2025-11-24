/******************************************************************************
 * \filestse_platform_crypto.c
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
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/asn.h>
#include "stse_conf.h"
#include "stselib.h"

/* Map STSE curve types to wolfCrypt curve IDs */
static int stse_platform_get_wc_ecc_curve_id(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return ECC_SECP256R1;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return ECC_SECP384R1;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return ECC_SECP521R1;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return ECC_BRAINPOOLP256R1;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return ECC_BRAINPOOLP384R1;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return ECC_BRAINPOOLP512R1;
#endif
    default:
        return -1;
    }
}

static size_t stse_platform_get_wc_ecc_pub_key_len(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return 65; /* 1 + 2*32 (uncompressed format) */
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return 97; /* 1 + 2*48 */
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return 133; /* 1 + 2*66 */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return 65;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return 97;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return 129; /* 1 + 2*64 */
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return CURVE25519_KEYSIZE;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return ED25519_PUB_KEY_SIZE;
#endif
    default:
        return 0u;
    }
}

static size_t stse_platform_get_wc_ecc_sig_len(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return 64; /* 2*32 (r,s) */
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return 96; /* 2*48 */
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return 132; /* 2*66 */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return 64;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return 96;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return 128; /* 2*64 */
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return 0; /* No signature with curve25519 */
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return ED25519_SIG_SIZE;
#endif
    default:
        return 0u;
    }
}

static size_t stse_platform_get_wc_ecc_priv_key_len(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return 32;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return 48;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return 66;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return 32;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return 48;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return 64;
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return CURVE25519_KEYSIZE;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return ED25519_KEY_SIZE;
#endif
    default:
        return 0u;
    }
}

stse_ReturnCode_t stse_platform_ecc_verify(
    stse_ecc_key_type_t key_type,
    const PLAT_UI8 *pPubKey,
    PLAT_UI8 *pDigest,
    PLAT_UI16 digestLen,
    PLAT_UI8 *pSignature) {
#if defined(STSE_CONF_ECC_NIST_P_256) || defined(STSE_CONF_ECC_NIST_P_384) || defined(STSE_CONF_ECC_NIST_P_521) ||                \
    defined(STSE_CONF_ECC_BRAINPOOL_P_256) || defined(STSE_CONF_ECC_BRAINPOOL_P_384) || defined(STSE_CONF_ECC_BRAINPOOL_P_512) || \
    defined(STSE_CONF_ECC_CURVE_25519) || defined(STSE_CONF_ECC_EDWARD_25519)
    int retval;

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        ed25519_key ed_key;
        int stat = 0;

        /* Import Ed25519 public key */
        retval = wc_ed25519_init(&ed_key);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_VERIFY_ERROR;
        }

        retval = wc_ed25519_import_public(pPubKey, ED25519_PUB_KEY_SIZE, &ed_key);
        if (retval != 0) {
            wc_ed25519_free(&ed_key);
            return STSE_PLATFORM_ECC_VERIFY_ERROR;
        }

        /* Verify EdDSA signature */
        retval = wc_ed25519_verify_msg(pSignature, ED25519_SIG_SIZE, pDigest, digestLen, &stat, &ed_key);
        wc_ed25519_free(&ed_key);

        if (retval != 0 || stat != 1) {
            return STSE_PLATFORM_ECC_VERIFY_ERROR;
        }
    } else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
    {
        ecc_key ecc;
        int stat = 0;
        int curve_id = stse_platform_get_wc_ecc_curve_id(key_type);

        if (curve_id < 0) {
            return STSE_PLATFORM_ECC_VERIFY_ERROR;
        }

        /* Initialize ECC key */
        retval = wc_ecc_init(&ecc);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_VERIFY_ERROR;
        }

        /* Import ECC public key (assuming uncompressed format: 0x04 || X || Y) */
        retval = wc_ecc_import_x963(pPubKey, stse_platform_get_wc_ecc_pub_key_len(key_type), &ecc);
        if (retval != 0) {
            wc_ecc_free(&ecc);
            return STSE_PLATFORM_ECC_VERIFY_ERROR;
        }

        /* Verify ECDSA signature (signature format: r || s) */
        retval = wc_ecc_verify_hash(pSignature, stse_platform_get_wc_ecc_sig_len(key_type),
                                     pDigest, digestLen, &stat, &ecc);
        wc_ecc_free(&ecc);

        if (retval != 0 || stat != 1) {
            return STSE_PLATFORM_ECC_VERIFY_ERROR;
        }
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_ECC_VERIFY_ERROR;
#endif /* STSE_CONF_ECC_NIST_P_256 || STSE_CONF_ECC_NIST_P_384 || STSE_CONF_ECC_NIST_P_521 ||\
          STSE_CONF_ECC_BRAINPOOL_P_256 || STSE_CONF_ECC_BRAINPOOL_P_384 || STSE_CONF_ECC_BRAINPOOL_P_512 ||\
          STSE_CONF_ECC_CURVE_25519 || STSE_CONF_ECC_EDWARD_25519 */
}

/* Private_key */
PLAT_UI8 static_c25519_priv_key[32] = {0x3D, 0xAC, 0x2A, 0xFF, 0x7A, 0x55, 0x9F, 0xAA,
                                       0xAC, 0x1B, 0xB6, 0x46, 0xE9, 0xD5, 0xE0, 0x50,
                                       0x28, 0x72, 0xFE, 0x9F, 0xD5, 0xE8, 0x3B, 0x7E,
                                       0x68, 0x28, 0x7A, 0xB3, 0xF4, 0x7E, 0x59, 0x8F};

/* Public_key */
PLAT_UI8 static_c25519_pub_key[32] = {0x59, 0x86, 0xA8, 0xA3, 0x51, 0xBB, 0x07, 0xCA,
                                      0x40, 0x01, 0x76, 0xF7, 0x66, 0x8A, 0x4F, 0xBF,
                                      0xA1, 0xA5, 0xE1, 0x9A, 0xCB, 0x57, 0x55, 0xF6,
                                      0x57, 0xF9, 0x43, 0xE9, 0xBC, 0x39, 0x54, 0x0B};

stse_ReturnCode_t stse_platform_ecc_generate_key_pair(
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *pPrivKey,
    PLAT_UI8 *pPubKey) {
#if defined(STSE_CONF_ECC_NIST_P_256) || defined(STSE_CONF_ECC_NIST_P_384) || defined(STSE_CONF_ECC_NIST_P_521) ||                \
    defined(STSE_CONF_ECC_BRAINPOOL_P_256) || defined(STSE_CONF_ECC_BRAINPOOL_P_384) || defined(STSE_CONF_ECC_BRAINPOOL_P_512) || \
    defined(STSE_CONF_ECC_CURVE_25519) || defined(STSE_CONF_ECC_EDWARD_25519)
    int retval;

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        ed25519_key ed_key;
        word32 priv_len = ED25519_KEY_SIZE;
        word32 pub_len = ED25519_PUB_KEY_SIZE;

        /* Initialize Ed25519 key */
        retval = wc_ed25519_init(&ed_key);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }

        /* Generate key pair using platform RNG */
        retval = wc_ed25519_make_key(&stse_platform_wolfcrypt_rng, ED25519_KEY_SIZE, &ed_key);
        if (retval != 0) {
            wc_ed25519_free(&ed_key);
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }

        /* Export private and public keys */
        retval = wc_ed25519_export_private_only(&ed_key, pPrivKey, &priv_len);
        if (retval != 0) {
            wc_ed25519_free(&ed_key);
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }

        retval = wc_ed25519_export_public(&ed_key, pPubKey, &pub_len);
        wc_ed25519_free(&ed_key);

        if (retval != 0) {
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }
    } else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
#ifdef STSE_CONF_ECC_CURVE_25519
    if (key_type == STSE_ECC_KT_CURVE25519) {
        /* Use static keys for Curve25519 as in original code */
        memcpy(pPrivKey, static_c25519_priv_key, 32);
        memcpy(pPubKey, static_c25519_pub_key, 32);
        retval = 0;
    } else
#endif /* STSE_CONF_ECC_CURVE_25519 */
    {
        ecc_key ecc;
        word32 priv_len, pub_len;
        int curve_id = stse_platform_get_wc_ecc_curve_id(key_type);

        if (curve_id < 0) {
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }

        /* Initialize ECC key */
        retval = wc_ecc_init(&ecc);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }

        /* Generate ECC key pair using platform RNG */
        retval = wc_ecc_make_key_ex(&stse_platform_wolfcrypt_rng, NULL, 
                                     stse_platform_get_wc_ecc_priv_key_len(key_type) * 8, 
                                     curve_id, &ecc);
        if (retval != 0) {
            wc_ecc_free(&ecc);
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }

        /* Export private key as raw bytes */
        priv_len = stse_platform_get_wc_ecc_priv_key_len(key_type);
        retval = wc_ecc_export_private_only(&ecc, pPrivKey, &priv_len);
        if (retval != 0) {
            wc_ecc_free(&ecc);
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }

        /* Export public key in X9.63 format (uncompressed) */
        pub_len = stse_platform_get_wc_ecc_pub_key_len(key_type);
        retval = wc_ecc_export_x963(&ecc, pPubKey, &pub_len);
        wc_ecc_free(&ecc);

        if (retval != 0) {
            return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
        }
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
#endif /* STSE_CONF_ECC_NIST_P_256 || STSE_CONF_ECC_NIST_P_384 || STSE_CONF_ECC_NIST_P_521 ||\
          STSE_CONF_ECC_BRAINPOOL_P_256 || STSE_CONF_ECC_BRAINPOOL_P_384 || STSE_CONF_ECC_BRAINPOOL_P_512 ||\
          STSE_CONF_ECC_CURVE_25519 || STSE_CONF_ECC_EDWARD_25519 */
}

#if defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED) || \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED) ||   \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED)

stse_ReturnCode_t stse_platform_ecc_sign(
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *pPrivKey,
    PLAT_UI8 *pDigest,
    PLAT_UI16 digestLen,
    PLAT_UI8 *pSignature) {
#if defined(STSE_CONF_ECC_NIST_P_256) || defined(STSE_CONF_ECC_NIST_P_384) || defined(STSE_CONF_ECC_NIST_P_521) ||                \
    defined(STSE_CONF_ECC_BRAINPOOL_P_256) || defined(STSE_CONF_ECC_BRAINPOOL_P_384) || defined(STSE_CONF_ECC_BRAINPOOL_P_512) || \
    defined(STSE_CONF_ECC_CURVE_25519) || defined(STSE_CONF_ECC_EDWARD_25519)
    int retval;

    if (pPrivKey == NULL) {
        return STSE_PLATFORM_INVALID_PARAMETER;
    }

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        ed25519_key ed_key;
        word32 sig_len = ED25519_SIG_SIZE;

        /* Initialize Ed25519 key */
        retval = wc_ed25519_init(&ed_key);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }

        /* Import private key */
        retval = wc_ed25519_import_private_only(pPrivKey, ED25519_KEY_SIZE, &ed_key);
        if (retval != 0) {
            wc_ed25519_free(&ed_key);
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }

        /* Sign message */
        retval = wc_ed25519_sign_msg(pDigest, digestLen, pSignature, &sig_len, &ed_key);
        wc_ed25519_free(&ed_key);

        if (retval != 0) {
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }
    } else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
    {
        ecc_key ecc;
        word32 sig_len = stse_platform_get_wc_ecc_sig_len(key_type);
        int curve_id = stse_platform_get_wc_ecc_curve_id(key_type);

        if (curve_id < 0) {
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }

        /* Initialize ECC key */
        retval = wc_ecc_init(&ecc);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }

        /* Import private key */
        retval = wc_ecc_import_private_key(pPrivKey, stse_platform_get_wc_ecc_priv_key_len(key_type),
                                            NULL, 0, &ecc);
        if (retval != 0) {
            wc_ecc_free(&ecc);
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }

        /* Set curve parameters */
        retval = wc_ecc_set_curve(&ecc, stse_platform_get_wc_ecc_priv_key_len(key_type) * 8, curve_id);
        if (retval != 0) {
            wc_ecc_free(&ecc);
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }

        /* Sign hash with platform RNG */
        retval = wc_ecc_sign_hash(pDigest, digestLen, pSignature, &sig_len, 
                                   &stse_platform_wolfcrypt_rng, NULL, &ecc);
        wc_ecc_free(&ecc);

        if (retval != 0) {
            return STSE_PLATFORM_ECC_SIGN_ERROR;
        }
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_ECC_SIGN_ERROR;
#endif /* STSE_CONF_ECC_NIST_P_256 || STSE_CONF_ECC_NIST_P_384 || STSE_CONF_ECC_NIST_P_521 ||\
          STSE_CONF_ECC_BRAINPOOL_P_256 || STSE_CONF_ECC_BRAINPOOL_P_384 || STSE_CONF_ECC_BRAINPOOL_P_512 ||\
          STSE_CONF_ECC_CURVE_25519 || STSE_CONF_ECC_EDWARD_25519 */
}
#endif /* STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED || STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED ||
STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED */

#if defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) ||                      \
    defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED) ||               \
    defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED) || \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) ||                 \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED) ||   \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED) ||          \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED)

stse_ReturnCode_t stse_platform_ecc_ecdh(
    stse_ecc_key_type_t key_type,
    const PLAT_UI8 *pPubKey,
    const PLAT_UI8 *pPrivKey,
    PLAT_UI8 *pSharedSecret) {
    int retval;

#ifdef STSE_CONF_ECC_CURVE_25519
    if (key_type == STSE_ECC_KT_CURVE25519) {
        curve25519_key priv, pub;
        word32 secret_len = CURVE25519_KEYSIZE;

        /* Initialize Curve25519 keys */
        retval = wc_curve25519_init(&priv);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        retval = wc_curve25519_init(&pub);
        if (retval != 0) {
            wc_curve25519_free(&priv);
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        /* Import keys */
        retval = wc_curve25519_import_private_raw(pPrivKey, CURVE25519_KEYSIZE, &priv);
        if (retval != 0) {
            wc_curve25519_free(&priv);
            wc_curve25519_free(&pub);
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        retval = wc_curve25519_import_public(pPubKey, CURVE25519_KEYSIZE, &pub);
        if (retval != 0) {
            wc_curve25519_free(&priv);
            wc_curve25519_free(&pub);
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        /* Compute shared secret */
        retval = wc_curve25519_shared_secret(&priv, &pub, pSharedSecret, &secret_len);
        wc_curve25519_free(&priv);
        wc_curve25519_free(&pub);

        if (retval != 0) {
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }
    } else
#endif /* STSE_CONF_ECC_CURVE_25519 */
    {
        ecc_key priv, pub;
        word32 secret_len = stse_platform_get_wc_ecc_priv_key_len(key_type);
        int curve_id = stse_platform_get_wc_ecc_curve_id(key_type);

        if (curve_id < 0) {
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        /* Initialize ECC keys */
        retval = wc_ecc_init(&priv);
        if (retval != 0) {
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        retval = wc_ecc_init(&pub);
        if (retval != 0) {
            wc_ecc_free(&priv);
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        /* Import private key */
        retval = wc_ecc_import_private_key(pPrivKey, stse_platform_get_wc_ecc_priv_key_len(key_type),
                                            NULL, 0, &priv);
        if (retval != 0) {
            wc_ecc_free(&priv);
            wc_ecc_free(&pub);
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        /* Set curve for private key */
        retval = wc_ecc_set_curve(&priv, stse_platform_get_wc_ecc_priv_key_len(key_type) * 8, curve_id);
        if (retval != 0) {
            wc_ecc_free(&priv);
            wc_ecc_free(&pub);
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        /* Import public key (X9.63 format) */
        retval = wc_ecc_import_x963(pPubKey, stse_platform_get_wc_ecc_pub_key_len(key_type), &pub);
        if (retval != 0) {
            wc_ecc_free(&priv);
            wc_ecc_free(&pub);
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }

        /* Compute shared secret */
        retval = wc_ecc_shared_secret(&priv, &pub, pSharedSecret, &secret_len);
        wc_ecc_free(&priv);
        wc_ecc_free(&pub);

        if (retval != 0) {
            return STSE_PLATFORM_ECC_ECDH_ERROR;
        }
    }

    return STSE_OK;
}
#endif /* STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED) ||
STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED || STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) ||
STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED || STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED ||
STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED */

#if defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED) ||               \
    defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED) || \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED) ||          \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED)

stse_ReturnCode_t stse_platform_nist_kw_encrypt(PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
                                                PLAT_UI8 *pKey, PLAT_UI8 key_length,
                                                PLAT_UI8 *pOutput, PLAT_UI32 *pOutput_length) {
    int retval;
    word32 output_len = *pOutput_length;

    /* Perform AES Key Wrap (NIST SP 800-38F) */
    retval = wc_AesKeyWrap(pKey, key_length, pPayload, payload_length, pOutput, output_len, NULL);
    if (retval < 0) {
        return STSE_PLATFORM_KEYWRAP_ERROR;
    }

    *pOutput_length = (PLAT_UI32)retval;

    return STSE_OK;
}
#endif /* STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED || STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED ||
STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED || STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED */
