/**
 * \file wolfssl_user_settings.h
 * \brief Custom wolfCrypt configuration for STSAFE-A120 examples
 *
 * This file overrides the default wolfCrypt configuration to enable only
 * the cryptographic features required by the STSAFE-A120 platform layer.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Platform configuration */
/* Note: WOLFSSL_USER_SETTINGS is defined as a compiler flag in .cproject files */
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define SINGLE_THREADED
#define NO_DEV_RANDOM
#define NO_OLD_RNGNAME  /* Prevent RNG macro conflict with STM32 RNG peripheral */
#define USER_TIME       /* Provide custom time function */
#define NO_ASN_TIME     /* Disable time validation in certificates */
#define XTIME(t) ((time_t)0)    /* Stub time function */
#define XGMTIME(c, t) (NULL)    /* Stub gmtime function */

/* Custom RNG - declare function before macro */
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
uint32_t stse_platform_generate_random(void);
#ifdef __cplusplus
}
#endif
#define CUSTOM_RAND_GENERATE  stse_platform_generate_random  /* Use platform RNG */

/* Disable TLS/SSL features - we only need crypto primitives */
#define NO_TLS
#define NO_WOLFSSL_SERVER
#define NO_WOLFSSL_CLIENT
#define WOLFCRYPT_ONLY
#define WOLFSSL_USER_IO  /* Disable default socket I/O */
#define WOLFSSL_NO_SOCK  /* No socket support needed */
#define NO_WRITEV        /* Disable writev functionality */

/* Enable required hash algorithms */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3

/* Enable AES */
#define HAVE_AES
#define HAVE_AES_CBC
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT

/* Enable CMAC */
#define WOLFSSL_CMAC

/* Enable HMAC and HKDF */
#define HAVE_HMAC
#define HAVE_HKDF

/* Enable ECC */
#define HAVE_ECC
#define HAVE_ECC_DHE
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT

/* Enable specific ECC curves */
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_ECC521
#define HAVE_ECC_BRAINPOOL
#define WOLFSSL_CUSTOM_CURVES  /* Required for Brainpool curves */
#define HAVE_CURVE25519
#define HAVE_ED25519

/* Enable AES key wrap (NIST SP 800-38F) */
#define HAVE_AES_KEYWRAP

/* Disable unused features to save space */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define NO_OLD_TLS
#define NO_SESSION_CACHE
/* Enable certificate and ASN.1 support for STSAFE operations */
/* #define NO_CERTS */
/* #define NO_ASN */
/* #define NO_CODING */

/* Performance and memory optimizations */
#define WOLFSSL_SMALL_STACK
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define NO_INLINE  /* Use non-inline functions to reduce code size */

/* Disable assembly optimizations (use C implementations for ARM Cortex-M4) */
#define TFM_NO_ASM
#define WOLFSSL_NO_ASM

/* Math library selection - use normal math (no fast math to save space) */
#define USE_SLOW_SHA
#define USE_SLOW_SHA2
#define USE_SLOW_SHA512

#endif /* WOLFSSL_USER_SETTINGS_H */
