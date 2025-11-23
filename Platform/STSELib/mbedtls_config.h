/**
 * \file mbedtls_config.h
 * \brief Custom MbedTLS configuration for STSAFE-A120 examples
 *
 * This file overrides the default MbedTLS configuration to enable only
 * the cryptographic features required by the STSAFE-A120 platform layer.
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* System support */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/* Enable required crypto modules */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CMAC_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_NIST_KW_C

/* Note: SHA3 is not yet available in MbedTLS 3.6.2 stable branch.
 * If SHA3 support is needed, please use a development version of MbedTLS
 * or wait for a future release that includes SHA3 support.
 * The platform code includes SHA3 conditionally via STSE_CONF_HASH_SHA_3_*
 * defines, which should not be enabled until SHA3 is available.
 */

/* Enable curves */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_BP256R1_ENABLED
#define MBEDTLS_ECP_DP_BP384R1_ENABLED
#define MBEDTLS_ECP_DP_BP512R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED

/* Bignum support */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

/* Disable unnecessary features to save space */
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_PK_C
#undef MBEDTLS_PEM_PARSE_C
#undef MBEDTLS_BASE64_C
#undef MBEDTLS_RSA_C
#undef MBEDTLS_DHM_C
#undef MBEDTLS_DES_C
#undef MBEDTLS_CAMELLIA_C
#undef MBEDTLS_ARIA_C
#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_POLY1305_C
#undef MBEDTLS_CHACHAPOLY_C
#undef MBEDTLS_GCM_C
#undef MBEDTLS_CCM_C

/* Performance and memory optimizations */
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_ECP_WINDOW_SIZE            2
#define MBEDTLS_ECP_FIXED_POINT_OPTIM      0

/* Check config */
#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
