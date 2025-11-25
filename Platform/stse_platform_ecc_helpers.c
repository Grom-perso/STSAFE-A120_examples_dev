#include "stse_platform_ecc_helpers.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <string.h>

int stse_platform_get_wc_ecc_curve_id(stse_ecc_key_type_t key_type) {
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

uint32_t stse_platform_get_wc_ecc_priv_key_len(stse_ecc_key_type_t key_type) {
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

stse_ReturnCode_t stse_platform_ecc_verify_with_rs(stse_ecc_key_type_t key_type,
                                                  const uint8_t *pPubKey,
                                                  uint8_t *pDigest,
                                                  uint16_t digestLen,
                                                  const uint8_t *pR,
                                                  uint32_t rLen,
                                                  const uint8_t *pS,
                                                  uint32_t sLen) {
    int retval;
    ecc_key ecc;
    int stat = 0;
    int curve_id = stse_platform_get_wc_ecc_curve_id(key_type);

    if (curve_id < 0) {
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }

    retval = wc_ecc_init(&ecc);
    if (retval != 0) {
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }

    // Format public key in X9.63 format (0x04 || X || Y)
    uint32_t coord_size = stse_platform_get_wc_ecc_priv_key_len(key_type);
    uint32_t raw_pub_key_len = coord_size * 2;
    unsigned char x963_pub_key[132]; // ECC_MAXSIZE * 2 + 1
    x963_pub_key[0] = 0x04;
    memcpy(&x963_pub_key[1], pPubKey, raw_pub_key_len);

    retval = wc_ecc_import_x963(x963_pub_key, raw_pub_key_len + 1, &ecc);
    if (retval != 0) {
        wc_ecc_free(&ecc);
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }

    // Convert raw R and S to DER format
    unsigned char der_sig[144]; // ECC_MAX_SIG_SIZE
    uint32_t der_sig_len = sizeof(der_sig);
    retval = wc_ecc_rs_raw_to_sig(pR, rLen, pS, sLen, der_sig, (word32*)&der_sig_len);
    if (retval != 0) {
        wc_ecc_free(&ecc);
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }

    retval = wc_ecc_verify_hash(der_sig, der_sig_len, pDigest, digestLen, &stat, &ecc);
    wc_ecc_free(&ecc);
    if (retval != 0 || stat != 1) {
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }
    return STSE_OK;
}
