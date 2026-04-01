/**
 ******************************************************************************
 * @file    stsafe_engine_so.c
 * @author  CS application team
 * @brief   STSAFE-A120 OpenSSL ENGINE – dynamically-loadable shared library
 *
 * This file builds into a standalone shared object (libstsafe_engine.so) that
 * OpenSSL can load at runtime without any changes to the application binary.
 * It exposes the standard OpenSSL dynamic-engine entry points:
 *
 *   v_check()      – ABI version check invoked by the dynamic loader
 *   bind_engine()  – sets up the ENGINE structure (called by OpenSSL loader)
 *
 * Once loaded (via openssl.cnf or ENGINE_load_dynamic()), the engine:
 *  - Opens the STSAFE-A120 device over I2C and keeps an internal handler.
 *  - Hooks ECDSA signing via a custom EC_KEY_METHOD so that every EC key
 *    created through ENGINE_load_private_key() uses the STSAFE for signing.
 *  - Exposes ENGINE_ctrl control commands for runtime configuration:
 *      I2C_BUS    – I2C bus number  (default: 1)
 *      I2C_SPEED  – I2C speed kHz  (default: 400)
 *      CERT_ZONE  – STSAFE data zone holding the leaf certificate (default: 0)
 *      KEY_SLOT   – STSAFE private key slot  (default: 0)
 *      LOAD_CERT  – Read X509 from a STSAFE zone (i=zone, p=X509 **)
 *
 * Build
 * -----
 *   make engine          (outputs build/libstsafe_engine.so)
 *
 * Installation
 * ------------
 *   Option A – system-wide (requires root):
 *     sudo cp build/libstsafe_engine.so $(openssl version -e | grep ENGINESDIR | cut -d'"' -f2)/
 *
 *   Option B – any path: set dynamic_path in openssl-stsafe.cnf
 *
 * Configuration via openssl.cnf
 * ------------------------------
 *   See Engine/openssl-stsafe.cnf for a ready-to-use template.
 *   Point OpenSSL at it with:
 *     export OPENSSL_CONF=/path/to/openssl-stsafe.cnf
 *
 * Testing from the command line
 * -----------------------------
 *   # Verify engine loads and shows its capabilities:
 *   OPENSSL_CONF=Engine/openssl-stsafe.cnf openssl engine -v -t stsafe
 *
 *   # Mutual-TLS test (server must request client cert):
 *   OPENSSL_CONF=Engine/openssl-stsafe.cnf \
 *     openssl s_client -engine stsafe \
 *                      -keyform ENGINE -key "0" \
 *                      -connect <server>:443
 *
 * Using from the TLS client example
 * ----------------------------------
 *   Compile with -DSTSAFE_USE_DYNAMIC_ENGINE, then set OPENSSL_CONF before
 *   running:
 *     make EXAMPLE=06_TLS_client CFLAGS="-DSTSAFE_USE_DYNAMIC_ENGINE \
 *                                        -DSTSAFE_ENGINE_SO_PATH=\\\"build/libstsafe_engine.so\\\""
 *     OPENSSL_CONF=Engine/openssl-stsafe.cnf ./build/06_TLS_client
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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
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

/* stse_conf.h is in the Engine/ directory (same directory as this file) and
 * is found via -I$(ENGINE_DIR) in the Makefile. */
#include "stse_conf.h"

/* -------------------------------------------------------------------------
 * Engine identity
 * ---------------------------------------------------------------------- */

#define STSAFE_ENGINE_ID   "stsafe"
#define STSAFE_ENGINE_NAME "STSAFE-A120 Hardware Engine"

/* -------------------------------------------------------------------------
 * Module-level state
 * ---------------------------------------------------------------------- */

/** STSAFE device handler — managed entirely by the engine */
static stse_Handler_t g_stse_handler;
static int            g_handler_initialized = 0;

/* Runtime-configurable parameters (set via ctrl commands or openssl.cnf) */
static uint8_t  g_i2c_bus   = 1;
static uint16_t g_i2c_speed = 400;
static uint8_t  g_cert_zone = 0;
static uint8_t  g_key_slot  = 0;

/** Custom EC_KEY_METHOD that overrides sign_sig */
static EC_KEY_METHOD *g_stsafe_ec_method = NULL;

/** ex_data index on EC_KEY objects to hold the stsafe context */
static int g_ec_key_ctx_idx = -1;

/* -------------------------------------------------------------------------
 * Internal types
 * ---------------------------------------------------------------------- */

typedef struct stsafe_ec_key_ctx {
    stse_Handler_t      *pSTSE;
    uint8_t              slot_number;
    stse_ecc_key_type_t  key_type;
} stsafe_ec_key_ctx_t;

/* -------------------------------------------------------------------------
 * Engine control commands
 * ---------------------------------------------------------------------- */

enum {
    STSAFE_CMD_I2C_BUS   = ENGINE_CMD_BASE,
    STSAFE_CMD_I2C_SPEED,
    STSAFE_CMD_CERT_ZONE,
    STSAFE_CMD_KEY_SLOT,
    STSAFE_CMD_LOAD_CERT,
};

static const ENGINE_CMD_DEFN g_cmd_defns[] = {
    {
        STSAFE_CMD_I2C_BUS, "I2C_BUS",
        "Linux I2C bus number for the STSAFE-A120 (/dev/i2c-N, default: 1)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_I2C_SPEED, "I2C_SPEED",
        "I2C bus speed in kHz (100 or 400, default: 400)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_CERT_ZONE, "CERT_ZONE",
        "STSAFE data zone holding the DER leaf certificate (default: 0)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_KEY_SLOT, "KEY_SLOT",
        "STSAFE private key slot used for ECDSA signing (default: 0)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_LOAD_CERT, "LOAD_CERT",
        "Read X509 from STSAFE zone i into *p (X509 **); internal use",
        ENGINE_CMD_FLAG_INTERNAL
    },
    { 0, NULL, NULL, 0 }  /* terminator */
};

/* -------------------------------------------------------------------------
 * Internal helper: load certificate from a STSAFE data zone
 * ---------------------------------------------------------------------- */

/**
 * @brief  Read a DER certificate from the STSAFE and return a decoded X509.
 * @param  zone  STSAFE data zone index.
 * @return Allocated X509 or NULL on error.  Caller must call X509_free().
 */
static X509 *stse_so_load_cert(uint8_t zone)
{
    uint16_t cert_size = 0;
    stse_ReturnCode_t ret;

    if (!g_handler_initialized) {
        fprintf(stderr, "stsafe_engine_so: handler not initialized\n");
        return NULL;
    }

    ret = stse_get_device_certificate_size(&g_stse_handler, zone, &cert_size);
    if (ret != STSE_OK || cert_size == 0) {
        fprintf(stderr,
                "stsafe_engine_so: stse_get_device_certificate_size failed "
                "(0x%04X)\n", (unsigned int)ret);
        return NULL;
    }

    uint8_t *buf = (uint8_t *)malloc(cert_size);
    if (buf == NULL) {
        fprintf(stderr, "stsafe_engine_so: out of memory for cert buffer\n");
        return NULL;
    }

    ret = stse_get_device_certificate(&g_stse_handler, zone, cert_size, buf);
    if (ret != STSE_OK) {
        fprintf(stderr,
                "stsafe_engine_so: stse_get_device_certificate failed "
                "(0x%04X)\n", (unsigned int)ret);
        free(buf);
        return NULL;
    }

    const uint8_t *p = buf;
    X509 *cert = d2i_X509(NULL, &p, cert_size);
    free(buf);

    if (cert == NULL) {
        fprintf(stderr,
                "stsafe_engine_so: d2i_X509 failed (invalid DER in zone %u)\n",
                (unsigned int)zone);
    }
    return cert;
}

/* -------------------------------------------------------------------------
 * Internal helper: create engine-backed EVP_PKEY for a given STSAFE slot
 * ---------------------------------------------------------------------- */

/**
 * @brief  Build an EVP_PKEY that routes ECDSA signing to a STSAFE slot.
 * @param  e           ENGINE handle (must have g_stsafe_ec_method set).
 * @param  slot        STSAFE private key slot number.
 * @param  key_type    ECC curve type.
 * @param  pub_ec_key  EC_KEY carrying the public point (curve + public key).
 * @return Newly allocated EVP_PKEY, or NULL on error.
 */
static EVP_PKEY *stse_so_create_engine_key(ENGINE              *e,
                                            uint8_t              slot,
                                            stse_ecc_key_type_t  key_type,
                                            EC_KEY              *pub_ec_key)
{
    if (g_ec_key_ctx_idx < 0) {
        fprintf(stderr, "stsafe_engine_so: ex_data index not allocated\n");
        return NULL;
    }

    EC_KEY *ec_key = EC_KEY_new_method(e);
    if (ec_key == NULL) {
        fprintf(stderr, "stsafe_engine_so: EC_KEY_new_method failed\n");
        return NULL;
    }

    const EC_GROUP *group = EC_KEY_get0_group(pub_ec_key);
    if (EC_KEY_set_group(ec_key, group) != 1) {
        fprintf(stderr, "stsafe_engine_so: EC_KEY_set_group failed\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    const EC_POINT *pub_pt = EC_KEY_get0_public_key(pub_ec_key);
    if (EC_KEY_set_public_key(ec_key, pub_pt) != 1) {
        fprintf(stderr, "stsafe_engine_so: EC_KEY_set_public_key failed\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    stsafe_ec_key_ctx_t *ctx =
        (stsafe_ec_key_ctx_t *)calloc(1, sizeof(stsafe_ec_key_ctx_t));
    if (ctx == NULL) {
        fprintf(stderr, "stsafe_engine_so: out of memory for key ctx\n");
        EC_KEY_free(ec_key);
        return NULL;
    }
    ctx->pSTSE       = &g_stse_handler;
    ctx->slot_number = slot;
    ctx->key_type    = key_type;

    if (EC_KEY_set_ex_data(ec_key, g_ec_key_ctx_idx, ctx) != 1) {
        fprintf(stderr, "stsafe_engine_so: EC_KEY_set_ex_data failed\n");
        free(ctx);
        EC_KEY_free(ec_key);
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        free(ctx);
        EC_KEY_free(ec_key);
        return NULL;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        free(ctx);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}

/* -------------------------------------------------------------------------
 * ECDSA sign_sig callback (same logic as static engine)
 * ---------------------------------------------------------------------- */

static ECDSA_SIG *stsafe_so_sign_sig(const unsigned char *dgst,
                                      int                  dgst_len,
                                      const BIGNUM        *in_kinv,
                                      const BIGNUM        *in_r,
                                      EC_KEY              *eckey)
{
    (void)in_kinv;
    (void)in_r;

    stsafe_ec_key_ctx_t *ctx =
        (stsafe_ec_key_ctx_t *)EC_KEY_get_ex_data(eckey, g_ec_key_ctx_idx);
    if (ctx == NULL) {
        fprintf(stderr, "stsafe_engine_so: no STSAFE context on EC_KEY\n");
        return NULL;
    }

    if (dgst == NULL || dgst_len <= 0) {
        fprintf(stderr, "stsafe_engine_so: invalid digest\n");
        return NULL;
    }

    uint16_t sig_size   = stse_ecc_info_table[ctx->key_type].signature_size;
    uint16_t coord_size = sig_size / 2U;

    if (sig_size == 0) {
        fprintf(stderr, "stsafe_engine_so: unknown signature size\n");
        return NULL;
    }

    uint8_t *raw_sig = (uint8_t *)calloc(1, sig_size);
    if (raw_sig == NULL) {
        fprintf(stderr, "stsafe_engine_so: OOM for signature buffer\n");
        return NULL;
    }

    stse_ReturnCode_t stse_ret = stse_ecc_generate_signature(
        ctx->pSTSE,
        ctx->slot_number,
        ctx->key_type,
        (uint8_t *)(uintptr_t)dgst,
        (uint16_t)dgst_len,
        raw_sig);

    if (stse_ret != STSE_OK) {
        fprintf(stderr,
                "stsafe_engine_so: stse_ecc_generate_signature failed "
                "(0x%04X)\n", (unsigned int)stse_ret);
        free(raw_sig);
        return NULL;
    }

    BIGNUM *r_bn = BN_bin2bn(raw_sig,              (int)coord_size, NULL);
    BIGNUM *s_bn = BN_bin2bn(raw_sig + coord_size, (int)coord_size, NULL);
    free(raw_sig);

    if (r_bn == NULL || s_bn == NULL) {
        BN_free(r_bn);
        BN_free(s_bn);
        return NULL;
    }

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == NULL) {
        BN_free(r_bn);
        BN_free(s_bn);
        return NULL;
    }

    if (ECDSA_SIG_set0(sig, r_bn, s_bn) != 1) {
        BN_free(r_bn);
        BN_free(s_bn);
        ECDSA_SIG_free(sig);
        return NULL;
    }

    return sig;
}

/* -------------------------------------------------------------------------
 * ENGINE callbacks
 * ---------------------------------------------------------------------- */

static int stsafe_so_init(ENGINE *e)
{
    (void)e;

    if (g_handler_initialized) {
        return 1;  /* idempotent */
    }

    stse_ReturnCode_t ret = stse_set_default_handler_value(&g_stse_handler);
    if (ret != STSE_OK) {
        fprintf(stderr,
                "stsafe_engine_so: stse_set_default_handler_value failed "
                "(0x%04X)\n", (unsigned int)ret);
        return 0;
    }

    g_stse_handler.device_type   = STSAFE_A120;
    g_stse_handler.io.busID      = g_i2c_bus;
    g_stse_handler.io.BusSpeed   = g_i2c_speed;

    ret = stse_init(&g_stse_handler);
    if (ret != STSE_OK) {
        fprintf(stderr,
                "stsafe_engine_so: stse_init failed (0x%04X) "
                "[i2c=%u speed=%u]\n",
                (unsigned int)ret,
                (unsigned int)g_i2c_bus,
                (unsigned int)g_i2c_speed);
        return 0;
    }

    g_handler_initialized = 1;
    fprintf(stderr,
            "stsafe_engine_so: STSAFE-A120 initialised on /dev/i2c-%u "
            "at %u kHz\n",
            (unsigned int)g_i2c_bus, (unsigned int)g_i2c_speed);
    return 1;
}

static int stsafe_so_finish(ENGINE *e)
{
    (void)e;
    g_handler_initialized = 0;
    return 1;
}

static int stsafe_so_destroy(ENGINE *e)
{
    (void)e;
    if (g_stsafe_ec_method != NULL) {
        EC_KEY_METHOD_free(g_stsafe_ec_method);
        g_stsafe_ec_method = NULL;
    }
    return 1;
}

/**
 * @brief  ENGINE ctrl callback.
 *
 * Handles both numeric config commands (from openssl.cnf or
 * ENGINE_ctrl_cmd()) and the internal LOAD_CERT command.
 *
 * openssl.cnf passes string values; the ENGINE framework converts them to
 * longs for numeric commands.  The LOAD_CERT command uses:
 *   i = zone number
 *   p = pointer to X509 * (output)
 */
static int stsafe_so_ctrl(ENGINE *e, int cmd, long i, void *p,
                           void (*f)(void))
{
    (void)e;
    (void)f;

    switch (cmd) {
    case STSAFE_CMD_I2C_BUS:
        g_i2c_bus = (uint8_t)i;
        return 1;

    case STSAFE_CMD_I2C_SPEED:
        g_i2c_speed = (uint16_t)i;
        return 1;

    case STSAFE_CMD_CERT_ZONE:
        g_cert_zone = (uint8_t)i;
        return 1;

    case STSAFE_CMD_KEY_SLOT:
        g_key_slot = (uint8_t)i;
        return 1;

    case STSAFE_CMD_LOAD_CERT: {
        if (p == NULL) {
            fprintf(stderr, "stsafe_engine_so: LOAD_CERT: p (X509 **) is NULL\n");
            return 0;
        }
        X509 **out = (X509 **)p;
        *out = stse_so_load_cert((uint8_t)i);
        return (*out != NULL) ? 1 : 0;
    }

    default:
        return 0;
    }
}

/**
 * @brief  ENGINE load_privkey callback.
 *
 * Called by OpenSSL when an application requests a private key from this
 * engine, e.g. via:
 *   ENGINE_load_private_key(e, key_id, NULL, NULL)
 *   openssl s_client -engine stsafe -keyform ENGINE -key "0"
 *
 * @param  key_id  Key identifier string. Accepted formats:
 *                   "N"    – use slot N, certificate from g_cert_zone
 *                   "N:Z"  – use slot N, certificate from zone Z
 * @return EVP_PKEY backed by STSAFE slot, or NULL on error.
 */
static EVP_PKEY *stsafe_so_load_privkey(ENGINE      *e,
                                         const char  *key_id,
                                         UI_METHOD   *ui,
                                         void        *cb_data)
{
    (void)ui;
    (void)cb_data;

    /* Parse key_id */
    uint8_t slot = g_key_slot;
    uint8_t zone = g_cert_zone;

    if (key_id != NULL && key_id[0] != '\0') {
        const char *colon = strchr(key_id, ':');
        if (colon != NULL) {
            slot = (uint8_t)atoi(key_id);
            zone = (uint8_t)atoi(colon + 1);
        } else {
            slot = (uint8_t)atoi(key_id);
        }
    }

    /* Load certificate to obtain the public key point */
    X509 *cert = stse_so_load_cert(zone);
    if (cert == NULL) {
        fprintf(stderr,
                "stsafe_engine_so: load_privkey: cert load from zone %u "
                "failed\n", (unsigned int)zone);
        return NULL;
    }

    EVP_PKEY *cert_pub = X509_get0_pubkey(cert);
    if (cert_pub == NULL || EVP_PKEY_id(cert_pub) != EVP_PKEY_EC) {
        fprintf(stderr,
                "stsafe_engine_so: load_privkey: certificate in zone %u "
                "does not contain an EC public key\n", (unsigned int)zone);
        X509_free(cert);
        return NULL;
    }

    EC_KEY *pub_ec_key = (EC_KEY *)(uintptr_t)EVP_PKEY_get0_EC_KEY(cert_pub);

    EVP_PKEY *pkey = stse_so_create_engine_key(e, slot,
                                                STSE_ECC_KT_NIST_P_256,
                                                pub_ec_key);
    X509_free(cert);

    if (pkey == NULL) {
        fprintf(stderr,
                "stsafe_engine_so: load_privkey: key creation for slot %u "
                "failed\n", (unsigned int)slot);
    } else {
        fprintf(stderr,
                "stsafe_engine_so: loaded private key slot %u (zone %u)\n",
                (unsigned int)slot, (unsigned int)zone);
    }

    return pkey;
}

/* -------------------------------------------------------------------------
 * EC_KEY_METHOD setup (shared with sign_sig hook)
 * ---------------------------------------------------------------------- */

static int stsafe_so_setup_ec_method(void)
{
    if (g_ec_key_ctx_idx == -1) {
        g_ec_key_ctx_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (g_ec_key_ctx_idx < 0) {
            fprintf(stderr,
                    "stsafe_engine_so: EC_KEY_get_ex_new_index failed\n");
            return 0;
        }
    }

    if (g_stsafe_ec_method == NULL) {
        g_stsafe_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
        if (g_stsafe_ec_method == NULL) {
            fprintf(stderr, "stsafe_engine_so: EC_KEY_METHOD_new failed\n");
            return 0;
        }

        int (*default_sign)(int, const unsigned char *, int,
                            unsigned char *, unsigned int *,
                            const BIGNUM *, const BIGNUM *, EC_KEY *);
        int (*default_sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);
        ECDSA_SIG *(*unused_sign_sig)(const unsigned char *, int,
                                      const BIGNUM *, const BIGNUM *,
                                      EC_KEY *);

        EC_KEY_METHOD_get_sign(EC_KEY_OpenSSL(),
                               &default_sign,
                               &default_sign_setup,
                               &unused_sign_sig);

        EC_KEY_METHOD_set_sign(g_stsafe_ec_method,
                               default_sign,
                               default_sign_setup,
                               stsafe_so_sign_sig);
    }

    return 1;
}

/* -------------------------------------------------------------------------
 * Dynamic engine entry point: bind_engine
 * ---------------------------------------------------------------------- */

/**
 * @brief  Populate the ENGINE structure.
 *
 * This function is called by OpenSSL's dynamic engine loader immediately
 * after the shared library is dlopen()ed.  It registers all callbacks,
 * control commands, and the ECDSA method override.
 *
 * @param  e   Blank ENGINE structure provided by OpenSSL loader.
 * @param  id  Engine ID requested by the caller (may be NULL).
 * @return 1 on success, 0 on failure.
 */
static int stsafe_so_bind(ENGINE *e, const char *id)
{
    /* Reject requests for a different engine ID */
    if (id != NULL && strcmp(id, STSAFE_ENGINE_ID) != 0) {
        return 0;
    }

    if (!stsafe_so_setup_ec_method()) {
        return 0;
    }

    if (!ENGINE_set_id(e, STSAFE_ENGINE_ID))                       return 0;
    if (!ENGINE_set_name(e, STSAFE_ENGINE_NAME))                   return 0;
    if (!ENGINE_set_init_function(e,    stsafe_so_init))           return 0;
    if (!ENGINE_set_finish_function(e,  stsafe_so_finish))         return 0;
    if (!ENGINE_set_destroy_function(e, stsafe_so_destroy))        return 0;
    if (!ENGINE_set_ctrl_function(e,    stsafe_so_ctrl))           return 0;
    if (!ENGINE_set_cmd_defns(e,        g_cmd_defns))              return 0;
    if (!ENGINE_set_EC(e,               g_stsafe_ec_method))       return 0;
    if (!ENGINE_set_load_privkey_function(e, stsafe_so_load_privkey)) return 0;

    return 1;
}

/* -------------------------------------------------------------------------
 * Dynamic loader entry points (must be exported symbols)
 * ---------------------------------------------------------------------- */

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(stsafe_so_bind)
