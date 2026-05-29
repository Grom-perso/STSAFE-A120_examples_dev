/**
 ******************************************************************************
 * @file    stsafe_engine.c
 * @author  CS application team
 * @brief   OpenSSL ENGINE implementation backed by STSAFE-A120 hardware
 *
 * Architecture
 * ------------
 * The engine hooks into OpenSSL's EC_KEY signing path via a custom
 * EC_KEY_METHOD.  When the TLS stack requests an ECDSA signature, the
 * sign_sig callback:
 *   1. Retrieves the STSAFE context (handler + key slot) stored in the
 *      EC_KEY's application-data slot (ex_data).
 *   2. Calls stse_ecc_generate_signature() to sign the digest inside the
 *      STSAFE-A120 secure element.
 *   3. Converts the raw r||s output to an ECDSA_SIG and returns it to
 *      OpenSSL, which DER-encodes it for the TLS record.
 *
 * The engine itself is a static singleton registered in-process via
 * ENGINE_add(); no shared-object loading is required.
 *
 ******************************************************************************
 *                      COPYRIGHT 2022 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include "stsafe_engine.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* STSELib */
#include "api/stse_device_authentication.h"
#include "api/stse_ecc.h"
#include "core/stse_generic_typedef.h"
#include "stselib.h"

/* -------------------------------------------------------------------------
 * Internal types
 * ---------------------------------------------------------------------- */

/**
 * @brief  Context stored in EC_KEY ex_data for each STSAFE-backed key.
 */
typedef struct stsafe_ec_key_ctx {
    stse_Handler_t      *pSTSE;       /**< Initialised STSAFE handler         */
    uint8_t              slot_number; /**< Private-key slot inside the STSAFE */
    stse_ecc_key_type_t  key_type;    /**< ECC curve type                      */
} stsafe_ec_key_ctx_t;

/* -------------------------------------------------------------------------
 * Module-level globals
 * ---------------------------------------------------------------------- */

/** Custom EC_KEY_METHOD that overrides the sign_sig function. */
static EC_KEY_METHOD *g_stsafe_ec_method = NULL;

/** ex_data index allocated for stsafe_ec_key_ctx_t on EC_KEY objects. */
static int g_ec_key_ctx_idx = -1;

/** The engine singleton. */
static ENGINE *g_stsafe_engine = NULL;

/* -------------------------------------------------------------------------
 * ECDSA sign_sig callback
 * ---------------------------------------------------------------------- */

/**
 * @brief  ECDSA sign_sig hook called by OpenSSL during TLS handshake.
 *
 * Receives the pre-computed digest, routes it to the STSAFE for signing,
 * and returns an ECDSA_SIG carrying the raw r || s values.
 *
 * @param  dgst      Pre-computed message digest.
 * @param  dgst_len  Length of @p dgst in bytes.
 * @param  in_kinv   Ignored (STSAFE generates its own ephemeral k).
 * @param  in_r      Ignored.
 * @param  eckey     EC_KEY whose ex_data holds the stsafe_ec_key_ctx_t.
 * @return ECDSA_SIG on success, NULL on failure.
 */
static ECDSA_SIG *stsafe_ecdsa_sign_sig(const unsigned char  *dgst,
                                         int                   dgst_len,
                                         const BIGNUM         *in_kinv,
                                         const BIGNUM         *in_r,
                                         EC_KEY               *eckey)
{
    (void)in_kinv;
    (void)in_r;

    /* Retrieve the STSAFE context attached to this EC_KEY */
    stsafe_ec_key_ctx_t *ctx =
        (stsafe_ec_key_ctx_t *)EC_KEY_get_ex_data(eckey, g_ec_key_ctx_idx);
    if (ctx == NULL) {
        fprintf(stderr, "stsafe_engine: no STSAFE context on EC_KEY\n");
        return NULL;
    }

    if (dgst == NULL || dgst_len <= 0) {
        fprintf(stderr, "stsafe_engine: invalid digest\n");
        return NULL;
    }

    /* Determine signature buffer size from the STSELib info table */
    uint16_t sig_size = stse_ecc_info_table[ctx->key_type].signature_size;
    if (sig_size == 0) {
        fprintf(stderr, "stsafe_engine: unknown signature size for key_type %d\n",
                (int)ctx->key_type);
        return NULL;
    }
    uint16_t coord_size = sig_size / 2U;

    /* Allocate a raw signature buffer (r || s, big-endian) */
    uint8_t *raw_sig = (uint8_t *)calloc(1, sig_size);
    if (raw_sig == NULL) {
        fprintf(stderr, "stsafe_engine: out of memory for signature buffer\n");
        return NULL;
    }

    /* Offload signing to STSAFE-A120 */
    stse_ReturnCode_t stse_ret = stse_ecc_generate_signature(
        ctx->pSTSE,
        ctx->slot_number,
        ctx->key_type,
        (uint8_t *)(uintptr_t)dgst, /* const-safe: STSELib reads only */
        (uint16_t)dgst_len,
        raw_sig);

    if (stse_ret != STSE_OK) {
        fprintf(stderr, "stsafe_engine: stse_ecc_generate_signature failed (0x%04X)\n",
                (unsigned int)stse_ret);
        free(raw_sig);
        return NULL;
    }

    /* Convert raw r || s to OpenSSL ECDSA_SIG */
    BIGNUM *r_bn = BN_bin2bn(raw_sig,              (int)coord_size, NULL);
    BIGNUM *s_bn = BN_bin2bn(raw_sig + coord_size, (int)coord_size, NULL);
    free(raw_sig);

    if (r_bn == NULL || s_bn == NULL) {
        BN_free(r_bn);
        BN_free(s_bn);
        fprintf(stderr, "stsafe_engine: BN_bin2bn failed\n");
        return NULL;
    }

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == NULL) {
        BN_free(r_bn);
        BN_free(s_bn);
        fprintf(stderr, "stsafe_engine: ECDSA_SIG_new failed\n");
        return NULL;
    }

    /* ECDSA_SIG_set0 takes ownership of r_bn and s_bn */
    if (ECDSA_SIG_set0(sig, r_bn, s_bn) != 1) {
        BN_free(r_bn);
        BN_free(s_bn);
        ECDSA_SIG_free(sig);
        fprintf(stderr, "stsafe_engine: ECDSA_SIG_set0 failed\n");
        return NULL;
    }

    return sig;
}

/* -------------------------------------------------------------------------
 * Engine lifecycle callbacks
 * ---------------------------------------------------------------------- */

static int stsafe_engine_init_cb(ENGINE *e)
{
    (void)e;
    return 1;
}

static int stsafe_engine_finish_cb(ENGINE *e)
{
    (void)e;
    return 1;
}

static int stsafe_engine_destroy_cb(ENGINE *e)
{
    (void)e;

    if (g_stsafe_ec_method != NULL) {
        EC_KEY_METHOD_free(g_stsafe_ec_method);
        g_stsafe_ec_method = NULL;
    }
    g_stsafe_engine = NULL;
    return 1;
}

/* -------------------------------------------------------------------------
 * Engine initialisation
 * ---------------------------------------------------------------------- */

/**
 * @brief  Build and register the STSAFE engine singleton.
 * @return Pointer to ENGINE, or NULL on failure.
 */
static ENGINE *stsafe_engine_create(void)
{
    ENGINE *e = ENGINE_new();
    if (e == NULL) {
        fprintf(stderr, "stsafe_engine: ENGINE_new failed\n");
        return NULL;
    }

    /* Set engine identity */
    if (!ENGINE_set_id(e, STSAFE_ENGINE_ID) ||
        !ENGINE_set_name(e, STSAFE_ENGINE_NAME)) {
        fprintf(stderr, "stsafe_engine: ENGINE_set_id/name failed\n");
        goto err;
    }

    /* Lifecycle callbacks */
    if (!ENGINE_set_init_function(e,    stsafe_engine_init_cb)    ||
        !ENGINE_set_finish_function(e,  stsafe_engine_finish_cb)  ||
        !ENGINE_set_destroy_function(e, stsafe_engine_destroy_cb)) {
        fprintf(stderr, "stsafe_engine: ENGINE_set_*_function failed\n");
        goto err;
    }

    /* Allocate ex_data index for our private key context on EC_KEY objects */
    if (g_ec_key_ctx_idx == -1) {
        g_ec_key_ctx_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (g_ec_key_ctx_idx < 0) {
            fprintf(stderr, "stsafe_engine: EC_KEY_get_ex_new_index failed\n");
            goto err;
        }
    }

    /* Build the custom EC_KEY_METHOD based on OpenSSL's default, but with
     * our sign_sig override.  The default sign() wrapper handles DER encoding
     * and will call our sign_sig() to produce the ECDSA_SIG. */
    if (g_stsafe_ec_method == NULL) {
        g_stsafe_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
        if (g_stsafe_ec_method == NULL) {
            fprintf(stderr, "stsafe_engine: EC_KEY_METHOD_new failed\n");
            goto err;
        }

        /* Retrieve the default sign and sign_setup functions to keep them */
        int (*default_sign)(int type,
                            const unsigned char *dgst, int dlen,
                            unsigned char *sig, unsigned int *siglen,
                            const BIGNUM *kinv, const BIGNUM *r,
                            EC_KEY *eckey);
        int (*default_sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                  BIGNUM **kinvp, BIGNUM **rp);
        ECDSA_SIG *(*unused_sign_sig)(const unsigned char *dgst, int dgst_len,
                                      const BIGNUM *in_kinv, const BIGNUM *in_r,
                                      EC_KEY *eckey);

        EC_KEY_METHOD_get_sign(EC_KEY_OpenSSL(),
                               &default_sign,
                               &default_sign_setup,
                               &unused_sign_sig);

        /* Replace sign_sig with our STSAFE implementation */
        EC_KEY_METHOD_set_sign(g_stsafe_ec_method,
                               default_sign,
                               default_sign_setup,
                               stsafe_ecdsa_sign_sig);
    }

    /* Register the EC method with the engine */
    if (!ENGINE_set_EC(e, g_stsafe_ec_method)) {
        fprintf(stderr, "stsafe_engine: ENGINE_set_EC failed\n");
        goto err;
    }

    /* Register so it can be looked up by ID */
    if (!ENGINE_add(e)) {
        fprintf(stderr, "stsafe_engine: ENGINE_add failed\n");
        goto err;
    }

    /* ENGINE_add() takes a reference; release our construction reference */
    ENGINE_free(e);

    /* Retrieve from the registry (now holds the canonical reference) */
    e = ENGINE_by_id(STSAFE_ENGINE_ID);
    if (e == NULL) {
        fprintf(stderr, "stsafe_engine: ENGINE_by_id failed after add\n");
        return NULL;
    }

    if (!ENGINE_init(e)) {
        fprintf(stderr, "stsafe_engine: ENGINE_init failed\n");
        ENGINE_free(e);
        return NULL;
    }

    return e;

err:
    ENGINE_free(e);
    return NULL;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

ENGINE *stsafe_engine_get(void)
{
    if (g_stsafe_engine == NULL) {
        g_stsafe_engine = stsafe_engine_create();
    }
    return g_stsafe_engine;
}

X509 *stsafe_engine_load_cert(stse_Handler_t *pSTSE, uint8_t zone)
{
    uint16_t cert_size = 0;
    stse_ReturnCode_t ret;

    if (pSTSE == NULL) {
        fprintf(stderr, "stsafe_engine: pSTSE is NULL\n");
        return NULL;
    }

    /* Query the size of the DER certificate stored in the STSAFE data zone */
    ret = stse_get_device_certificate_size(pSTSE, zone, &cert_size);
    if (ret != STSE_OK || cert_size == 0) {
        fprintf(stderr,
                "stsafe_engine: stse_get_device_certificate_size failed (0x%04X)\n",
                (unsigned int)ret);
        return NULL;
    }

    uint8_t *cert_buf = (uint8_t *)malloc(cert_size);
    if (cert_buf == NULL) {
        fprintf(stderr, "stsafe_engine: out of memory for cert buffer\n");
        return NULL;
    }

    /* Read the DER certificate */
    ret = stse_get_device_certificate(pSTSE, zone, cert_size, cert_buf);
    if (ret != STSE_OK) {
        fprintf(stderr,
                "stsafe_engine: stse_get_device_certificate failed (0x%04X)\n",
                (unsigned int)ret);
        free(cert_buf);
        return NULL;
    }

    /* Decode from DER */
    const uint8_t *p = cert_buf;
    X509 *cert = d2i_X509(NULL, &p, cert_size);
    free(cert_buf);

    if (cert == NULL) {
        fprintf(stderr, "stsafe_engine: d2i_X509 failed – invalid DER in zone %u\n",
                (unsigned int)zone);
    }
    return cert;
}

EVP_PKEY *stsafe_engine_load_key(ENGINE              *e,
                                  stse_Handler_t      *pSTSE,
                                  uint8_t              slot_number,
                                  stse_ecc_key_type_t  key_type,
                                  EC_KEY              *pub_ec_key)
{
    if (e == NULL || pSTSE == NULL || pub_ec_key == NULL) {
        fprintf(stderr, "stsafe_engine_load_key: invalid argument\n");
        return NULL;
    }

    if (g_ec_key_ctx_idx < 0) {
        fprintf(stderr, "stsafe_engine_load_key: engine not initialised\n");
        return NULL;
    }

    /* Create a new EC_KEY that will use our custom method via the engine */
    EC_KEY *ec_key = EC_KEY_new_method(e);
    if (ec_key == NULL) {
        fprintf(stderr, "stsafe_engine_load_key: EC_KEY_new_method failed\n");
        return NULL;
    }

    /* Copy the curve group from the certificate's public key */
    const EC_GROUP *group = EC_KEY_get0_group(pub_ec_key);
    if (EC_KEY_set_group(ec_key, group) != 1) {
        fprintf(stderr, "stsafe_engine_load_key: EC_KEY_set_group failed\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    /* Copy the public point – OpenSSL uses it for key validation and logging */
    const EC_POINT *pub_point = EC_KEY_get0_public_key(pub_ec_key);
    if (EC_KEY_set_public_key(ec_key, pub_point) != 1) {
        fprintf(stderr, "stsafe_engine_load_key: EC_KEY_set_public_key failed\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    /* Attach STSAFE context – the sign_sig callback retrieves it from here */
    stsafe_ec_key_ctx_t *ctx =
        (stsafe_ec_key_ctx_t *)calloc(1, sizeof(stsafe_ec_key_ctx_t));
    if (ctx == NULL) {
        fprintf(stderr, "stsafe_engine_load_key: out of memory\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    ctx->pSTSE       = pSTSE;
    ctx->slot_number = slot_number;
    ctx->key_type    = key_type;

    if (EC_KEY_set_ex_data(ec_key, g_ec_key_ctx_idx, ctx) != 1) {
        fprintf(stderr, "stsafe_engine_load_key: EC_KEY_set_ex_data failed\n");
        free(ctx);
        EC_KEY_free(ec_key);
        return NULL;
    }

    /* Wrap in an EVP_PKEY */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        free(ctx);
        EC_KEY_free(ec_key);
        fprintf(stderr, "stsafe_engine_load_key: EVP_PKEY_new failed\n");
        return NULL;
    }

    /* EVP_PKEY_assign_EC_KEY transfers ownership of ec_key to pkey */
    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        fprintf(stderr, "stsafe_engine_load_key: EVP_PKEY_assign_EC_KEY failed\n");
        free(ctx);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}
