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

static size_t stse_platform_get_ecc_priv_key_len(stse_ecc_key_type_t key_type) {
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
    mbedtls_ecp_group_id grp_id;
    mbedtls_ecp_keypair ecp_keypair;
    mbedtls_mpi r, s;
    size_t sig_half_len;

    /* Note: EdDSA (Ed25519) is not directly supported by standard mbedtls_ecdsa APIs */
    /* For now, we'll implement ECDSA verify. EdDSA would require additional work */
#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        /* EdDSA verification would require different implementation */
        /* This is a simplified placeholder - full EdDSA support needs more work */
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }
#endif

    grp_id = stse_platform_get_mbedtls_ecp_group_id(key_type);
    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }

    mbedtls_ecp_keypair_init(&ecp_keypair);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    /* Load curve parameters */
    retval = mbedtls_ecp_group_load(&ecp_keypair.grp, grp_id);
    if (retval != 0) {
        goto cleanup;
    }

    /* Import public key */
    retval = mbedtls_ecp_point_read_binary(&ecp_keypair.grp, &ecp_keypair.Q,
                                           pPubKey, stse_platform_get_ecc_pub_key_len(key_type));
    if (retval != 0) {
        goto cleanup;
    }

    /* Split signature into r and s components */
    sig_half_len = stse_platform_get_ecc_sig_len(key_type) / 2;
    retval = mbedtls_mpi_read_binary(&r, pSignature, sig_half_len);
    if (retval != 0) {
        goto cleanup;
    }
    retval = mbedtls_mpi_read_binary(&s, pSignature + sig_half_len, sig_half_len);
    if (retval != 0) {
        goto cleanup;
    }

    /* Verify ECDSA signature */
    retval = mbedtls_ecdsa_verify(&ecp_keypair.grp, pDigest, digestLen,
                                  &ecp_keypair.Q, &r, &s);

cleanup:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&ecp_keypair);

    if (retval != 0) {
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
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
    mbedtls_ecp_group_id grp_id;
    mbedtls_ecp_keypair ecp_keypair;
    size_t olen;

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        /* EdDSA key generation would require different implementation */
        /* This is a simplified placeholder - full EdDSA support needs more work */
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }
#endif

#ifdef STSE_CONF_ECC_CURVE_25519
    if (key_type == STSE_ECC_KT_CURVE25519) {
        /* Use static key pair for Curve25519 */
        memcpy(pPrivKey, static_c25519_priv_key, 32);
        memcpy(pPubKey, static_c25519_pub_key, 32);
        return STSE_OK;
    }
#endif

    grp_id = stse_platform_get_mbedtls_ecp_group_id(key_type);
    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }

    mbedtls_ecp_keypair_init(&ecp_keypair);

    /* Load curve parameters */
    retval = mbedtls_ecp_group_load(&ecp_keypair.grp, grp_id);
    if (retval != 0) {
        mbedtls_ecp_keypair_free(&ecp_keypair);
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }

    /* Generate key pair using platform RNG */
    retval = mbedtls_ecp_gen_keypair(&ecp_keypair.grp, &ecp_keypair.d, &ecp_keypair.Q,
                                     stse_platform_generate_random, NULL);
    if (retval != 0) {
        mbedtls_ecp_keypair_free(&ecp_keypair);
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }

    /* Export private key */
    retval = mbedtls_mpi_write_binary(&ecp_keypair.d, pPrivKey,
                                      stse_platform_get_ecc_priv_key_len(key_type));
    if (retval != 0) {
        mbedtls_ecp_keypair_free(&ecp_keypair);
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }

    /* Export public key in uncompressed format */
    retval = mbedtls_ecp_point_write_binary(&ecp_keypair.grp, &ecp_keypair.Q,
                                            MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                            pPubKey, stse_platform_get_ecc_pub_key_len(key_type));
    if (retval != 0) {
        mbedtls_ecp_keypair_free(&ecp_keypair);
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }

    mbedtls_ecp_keypair_free(&ecp_keypair);

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
    mbedtls_ecp_group_id grp_id;
    mbedtls_ecp_keypair ecp_keypair;
    mbedtls_mpi r, s;
    size_t sig_half_len;

    if (pPrivKey == NULL) {
        return STSE_PLATFORM_INVALID_PARAMETER;
    }

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519) {
        /* EdDSA signing would require different implementation */
        /* This is a simplified placeholder - full EdDSA support needs more work */
        return STSE_PLATFORM_ECC_SIGN_ERROR;
    }
#endif

    grp_id = stse_platform_get_mbedtls_ecp_group_id(key_type);
    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        return STSE_PLATFORM_ECC_SIGN_ERROR;
    }

    mbedtls_ecp_keypair_init(&ecp_keypair);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    /* Load curve parameters */
    retval = mbedtls_ecp_group_load(&ecp_keypair.grp, grp_id);
    if (retval != 0) {
        goto cleanup;
    }

    /* Import private key */
    retval = mbedtls_mpi_read_binary(&ecp_keypair.d, pPrivKey,
                                     stse_platform_get_ecc_priv_key_len(key_type));
    if (retval != 0) {
        goto cleanup;
    }

    /* Sign message */
    retval = mbedtls_ecdsa_sign(&ecp_keypair.grp, &r, &s, &ecp_keypair.d,
                                pDigest, digestLen,
                                stse_platform_generate_random, NULL);
    if (retval != 0) {
        goto cleanup;
    }

    /* Export signature (r,s) */
    sig_half_len = stse_platform_get_ecc_sig_len(key_type) / 2;
    retval = mbedtls_mpi_write_binary(&r, pSignature, sig_half_len);
    if (retval != 0) {
        goto cleanup;
    }
    retval = mbedtls_mpi_write_binary(&s, pSignature + sig_half_len, sig_half_len);

cleanup:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&ecp_keypair);

    if (retval != 0) {
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
    int retval;
    mbedtls_ecp_group_id grp_id;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q_peer;
    mbedtls_mpi d_local, z;
    size_t olen;

    grp_id = stse_platform_get_mbedtls_ecp_group_id(key_type);
    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        return STSE_PLATFORM_ECC_ECDH_ERROR;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q_peer);
    mbedtls_mpi_init(&d_local);
    mbedtls_mpi_init(&z);

    /* Load curve parameters */
    retval = mbedtls_ecp_group_load(&grp, grp_id);
    if (retval != 0) {
        goto cleanup;
    }

    /* Import local private key */
    retval = mbedtls_mpi_read_binary(&d_local, pPrivKey,
                                     stse_platform_get_ecc_priv_key_len(key_type));
    if (retval != 0) {
        goto cleanup;
    }

    /* Import peer public key */
    retval = mbedtls_ecp_point_read_binary(&grp, &Q_peer, pPubKey,
                                           stse_platform_get_ecc_pub_key_len(key_type));
    if (retval != 0) {
        goto cleanup;
    }

    /* Compute shared secret: z = d_local * Q_peer */
    retval = mbedtls_ecdh_compute_shared(&grp, &z, &Q_peer, &d_local,
                                         stse_platform_generate_random, NULL);
    if (retval != 0) {
        goto cleanup;
    }

    /* Export shared secret (x-coordinate of the result) */
    retval = mbedtls_mpi_write_binary(&z, pSharedSecret,
                                      stse_platform_get_ecc_priv_key_len(key_type));

cleanup:
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d_local);
    mbedtls_ecp_point_free(&Q_peer);
    mbedtls_ecp_group_free(&grp);

    if (retval != 0) {
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
