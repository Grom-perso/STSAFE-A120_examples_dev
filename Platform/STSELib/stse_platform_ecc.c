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

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/nist_kw.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "stse_conf.h"
#include "stselib.h"

static mbedtls_ecp_group_id stse_platform_get_mbedtls_ecp_group_id(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return MBEDTLS_ECP_DP_SECP256R1;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return MBEDTLS_ECP_DP_SECP384R1;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return MBEDTLS_ECP_DP_SECP521R1;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return MBEDTLS_ECP_DP_BP256R1;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return MBEDTLS_ECP_DP_BP384R1;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return MBEDTLS_ECP_DP_BP512R1;
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return MBEDTLS_ECP_DP_CURVE25519;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return MBEDTLS_ECP_DP_CURVE25519;  /* MbedTLS uses Curve25519 for Ed25519 operations */
#endif
    default:
        return MBEDTLS_ECP_DP_NONE;
    }
}

static size_t stse_platform_get_ecc_pub_key_len(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return 65;  /* 1 + 2*32 for uncompressed format */
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return 97;  /* 1 + 2*48 for uncompressed format */
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return 133;  /* 1 + 2*66 for uncompressed format */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return 65;  /* 1 + 2*32 for uncompressed format */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return 97;  /* 1 + 2*48 for uncompressed format */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return 129;  /* 1 + 2*64 for uncompressed format */
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return 32;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return 32;
#endif
    default:
        return 0u;
    }
}

static size_t stse_platform_get_ecc_sig_len(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return 64;  /* 2*32 for r,s */
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return 96;  /* 2*48 for r,s */
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return 132;  /* 2*66 for r,s */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return 64;  /* 2*32 for r,s */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return 96;  /* 2*48 for r,s */
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return 128;  /* 2*64 for r,s */
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return 0; /* No signature with curve25519 */
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return 64;
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
    cmox_ecc_retval_t retval;
    PLAT_UI32 faultCheck;

    /*- Set ECC context */
    cmox_ecc_construct(&Ecc_Ctx,                /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,   /* Small math functions */
                       cmox_math_buffer,        /* Crypto math buffer */
                       sizeof(cmox_math_buffer) /* buffer size */
    );

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        /* - Perform EDDSA verify */
        retval = cmox_eddsa_verify(&Ecc_Ctx,                                         /* ECC context */
                                   stse_platform_get_cmox_ecc_impl(key_type),        /* Curve param */
                                   pPubKey,                                          /* Public key */
                                   stse_platform_get_cmox_ecc_pub_key_len(key_type), /* Public key length */
                                   pDigest,                                          /* Message */
                                   digestLen,                                        /* Message length */
                                   pSignature,                                       /* Pointer to signature */
                                   stse_platform_get_cmox_ecc_sig_len(key_type),     /* Signature size */
                                   &faultCheck                                       /* Fault check variable */
        );
    } else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
    {
        /* - Perform ECDSA verify */
        retval = cmox_ecdsa_verify(&Ecc_Ctx,                                         /* ECC context */
                                   stse_platform_get_cmox_ecc_impl(key_type),        /* Curve : SECP256R1 */
                                   pPubKey,                                          /* Public key */
                                   stse_platform_get_cmox_ecc_pub_key_len(key_type), /* Public key length */
                                   pDigest,                                          /* Message */
                                   digestLen,                                        /* Message length */
                                   pSignature,                                       /* Pointer to signature */
                                   stse_platform_get_cmox_ecc_sig_len(key_type),     /* Signature size */
                                   &faultCheck                                       /* Fault check variable */
        );
    }

    /* - Clear ECC context */
    cmox_ecc_cleanup(&Ecc_Ctx);

    if (retval != CMOX_ECC_AUTH_SUCCESS) {
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_ECC_VERIFY_ERROR;
#endif /* STSE_CONF_ECC_NIST_P_256 || STSE_CONF_ECC_NIST_P_384 || STSE_CONF_ECC_NIST_P_521 ||\
          STSE_CONF_ECC_BRAINPOOL_P_256 || STSE_CONF_ECC_BRAINPOOL_P_384 || STSE_CONF_ECC_BRAINPOOL_P_512 ||\
          STSE_CONF_ECC_CURVE_25519 || STSE_CONF_ECC_EDWARD_25519 */
}

static size_t stse_platform_get_cmox_ecc_priv_key_len(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return CMOX_ECC_SECP256R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return CMOX_ECC_SECP384R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return CMOX_ECC_SECP521R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return CMOX_ECC_BPP256R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return CMOX_ECC_BPP384R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return CMOX_ECC_BPP512R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return CMOX_ECC_CURVE25519_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return CMOX_ECC_ED25519_PRIVKEY_LEN;
#endif
    default:
        return 0u;
    }
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
    cmox_ecc_retval_t retval;

    /*- Set ECC context */
    cmox_ecc_construct(&Ecc_Ctx,                /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,   /* Small math functions */
                       cmox_math_buffer,        /* Crypto math buffer */
                       sizeof(cmox_math_buffer) /* buffer size */
    );

    /* Minimum random length equal the private key length */
    size_t randomLength = stse_platform_get_cmox_ecc_priv_key_len(key_type);
    /* Align the random length to modulo 4 */
    randomLength += 4 - (randomLength & 0x3);
    /* Add 32bytes to random length if the key is Curve25519 because it will use the Ed25519 key gen */
#ifdef STSE_CONF_ECC_CURVE_25519
    randomLength += ((key_type == STSE_ECC_KT_CURVE25519) ? 32 : 0);
#endif /* STSE_CONF_ECC_CURVE_25519 */
    /* Retry loop in case the RNG isn't strong enough */
    do {
        /* - Generate a random number */
        PLAT_UI8 randomNumber[randomLength];
        for (uint8_t i = 0; i < randomLength; i += 4) {
            *((PLAT_UI32 *)&randomNumber[i]) = stse_platform_generate_random();
        }

        /*- Generate EdDSA key pair */
#ifdef STSE_CONF_ECC_EDWARD_25519
        if (key_type == STSE_ECC_KT_ED25519) {
            retval = cmox_eddsa_keyGen(&Ecc_Ctx,                                  /* ECC context */
                                       stse_platform_get_cmox_ecc_impl(key_type), /* Curve param */
                                       randomNumber,                              /* Random number */
                                       randomLength,                              /* Random number length */
                                       pPrivKey,                                  /* Private key */
                                       NULL,                                      /* Private key length*/
                                       pPubKey,                                   /* Public key */
                                       NULL);                                     /* Public key length */
        } else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
#ifdef STSE_CONF_ECC_CURVE_25519
            if (key_type == STSE_ECC_KT_CURVE25519) {
            memcpy(pPrivKey, static_c25519_priv_key, 32);
            memcpy(pPubKey, static_c25519_pub_key, 32);

            retval = CMOX_ECC_SUCCESS;
        } else
#endif /* STSE_CONF_ECC_CURVE_25519 */
        {
            retval = cmox_ecdsa_keyGen(&Ecc_Ctx,                                  /* ECC context */
                                       stse_platform_get_cmox_ecc_impl(key_type), /* Curve param */
                                       randomNumber,                              /* Random number */
                                       randomLength,                              /* Random number length */
                                       pPrivKey,                                  /* Private key */
                                       NULL,                                      /* Private key length*/
                                       pPubKey,                                   /* Public key */
                                       NULL);                                     /* Public key length */
        }
    } while (retval == CMOX_ECC_ERR_WRONG_RANDOM);

    /* - Clear ECC context */
    cmox_ecc_cleanup(&Ecc_Ctx);

    if (retval != CMOX_ECC_SUCCESS) {
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
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
    cmox_ecc_retval_t retval;

    if (pPrivKey == NULL) {
        return STSE_PLATFORM_INVALID_PARAMETER;
    }

    /*- Set ECC context */
    cmox_ecc_construct(&Ecc_Ctx,                /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,   /* Small math functions */
                       cmox_math_buffer,        /* Crypto math buffer */
                       sizeof(cmox_math_buffer) /* buffer size */
    );

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        /* - Perform EDDSA sign */
        retval = cmox_eddsa_sign(&Ecc_Ctx,                                          /* ECC context */
                                 stse_platform_get_cmox_ecc_impl(key_type),         /* Curve param */
                                 pPrivKey,                                          /* Private key */
                                 stse_platform_get_cmox_ecc_priv_key_len(key_type), /* Private key length*/
                                 pDigest,                                           /* Message */
                                 digestLen,                                         /* Message length */
                                 pSignature,                                        /* Signature */
                                 NULL                                               /* Signature length */
        );
    } else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
    {
        do {
            /* - Generate a random number */
            size_t randomLength = stse_platform_get_cmox_ecc_priv_key_len(key_type) + (4 - (stse_platform_get_cmox_ecc_priv_key_len(key_type) & 0x3));
            PLAT_UI8 randomNumber[randomLength];
            for (uint8_t i = 0; i < randomLength; i += 4) {
                *((PLAT_UI32 *)&randomNumber[i]) = stse_platform_generate_random();
            }

            /* - Perform ECDSA sign */
            retval = cmox_ecdsa_sign(&Ecc_Ctx,                                  /* ECC context */
                                     stse_platform_get_cmox_ecc_impl(key_type), /* Curve param */
                                     randomNumber,
                                     stse_platform_get_cmox_ecc_priv_key_len(key_type),
                                     pPrivKey,                                          /* Private key */
                                     stse_platform_get_cmox_ecc_priv_key_len(key_type), /* Private key length*/
                                     pDigest,                                           /* Message */
                                     digestLen,                                         /* Message length */
                                     pSignature,                                        /* Signature */
                                     NULL                                               /* Signature length */
            );
        } while (retval == CMOX_ECC_ERR_WRONG_RANDOM);
    }

    /* - Clear ECC context */
    cmox_ecc_cleanup(&Ecc_Ctx);

    if (retval != CMOX_ECC_SUCCESS) {
        return STSE_PLATFORM_ECC_SIGN_ERROR;
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
    cmox_ecc_retval_t retval;

    /*- Set ECC context */
    cmox_ecc_construct(&Ecc_Ctx,                /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,   /* Small math functions */
                       cmox_math_buffer,        /* Crypto math buffer */
                       sizeof(cmox_math_buffer) /* buffer size */
    );

    retval = cmox_ecdh(&Ecc_Ctx,                                          /* ECC context */
                       stse_platform_get_cmox_ecc_impl(key_type),         /* Curve param */
                       pPrivKey,                                          /* Private key (local) */
                       stse_platform_get_cmox_ecc_priv_key_len(key_type), /* Private key length*/
                       pPubKey,                                           /* Public key (remote) */
                       stse_platform_get_cmox_ecc_pub_key_len(key_type),  /* Public key length */
                       pSharedSecret,                                     /* Shared secret */
                       NULL                                               /* Shared secret length */
    );

    /* - Clear ECC context */
    cmox_ecc_cleanup(&Ecc_Ctx);

    if (retval != CMOX_ECC_SUCCESS) {
        return STSE_PLATFORM_ECC_ECDH_ERROR;
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
    mbedtls_nist_kw_context kw_ctx;
    size_t output_length = 0;

    mbedtls_nist_kw_init(&kw_ctx);

    /* Set key wrap key */
    retval = mbedtls_nist_kw_setkey(&kw_ctx,
                                    MBEDTLS_CIPHER_ID_AES,
                                    pKey,
                                    key_length * 8,
                                    1);  /* 1 for wrap (encrypt) */
    if (retval != 0) {
        mbedtls_nist_kw_free(&kw_ctx);
        return STSE_PLATFORM_KEYWRAP_ERROR;
    }

    /* Perform key wrap */
    retval = mbedtls_nist_kw_wrap(&kw_ctx,
                                  MBEDTLS_KW_MODE_KW,
                                  pPayload,
                                  payload_length,
                                  pOutput,
                                  &output_length,
                                  *pOutput_length);

    mbedtls_nist_kw_free(&kw_ctx);

    if (retval != 0) {
        return STSE_PLATFORM_KEYWRAP_ERROR;
    }

    *pOutput_length = (PLAT_UI32)output_length;

    return STSE_OK;
}
#endif /* STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED || STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED ||
			STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED || STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED */
