/**
 ******************************************************************************
 * @file    stsafe_engine_so.c
 * @author  CS application team
 * @brief   STSAFE-A120 OpenSSL ENGINE – dynamically-loadable shared library
 *          backed by the STSELib PKCS#11 provider layer
 *
 * This file builds into a standalone shared object (libstsafe_engine.so) that
 * OpenSSL can load at runtime without any changes to the application binary.
 * It exposes the standard OpenSSL dynamic-engine entry points:
 *
 *   v_check()      – ABI version check invoked by the dynamic loader
 *   bind_engine()  – sets up the ENGINE structure (called by OpenSSL loader)
 *
 * Architecture
 * ------------
 * All cryptographic operations are routed through the PKCS#11 Cryptoki layer
 * provided by STSELib (sal/pkcs11/).  The engine does NOT call STSELib
 * functions directly; instead it uses the standard C_* PKCS#11 functions:
 *
 *   C_Initialize / C_Finalize   – device open/close
 *   C_OpenSession / C_CloseSession
 *   C_FindObjects{Init,Find,Final} + C_GetAttributeValue(CKA_VALUE)
 *                               – certificate loading from STSAFE data zones
 *   C_SignInit + C_Sign         – ECDSA signing using CKM_ECDSA (pre-hashed)
 *
 * Once loaded (via openssl.cnf or ENGINE_load_dynamic()), the engine:
 *  - Initialises the PKCS#11 token via stse_pkcs11_set_config + C_Initialize.
 *  - Opens a long-lived read-only PKCS#11 session.
 *  - Hooks ECDSA signing via a custom EC_KEY_METHOD so that every EC key
 *    created through ENGINE_load_private_key() uses the STSAFE for signing.
 *  - Exposes ENGINE_ctrl control commands for runtime configuration:
 *      I2C_BUS    – I2C bus number (string or numeric, default: 1)
 *      I2C_SPEED  – I2C speed in kHz (numeric, default: 400)
 *      CERT_ZONE  – STSAFE data zone holding the leaf certificate (default: 0)
 *      KEY_SLOT   – STSAFE private key slot (default: 0)
 *      LOAD_CERT  – Read X509 from STSAFE zone i into *(X509 **)p
 *
 * Build
 * -----
 *   make engine          (outputs build/libstsafe_engine.so)
 *   make pkcs11          (outputs build/libstsafe_pkcs11.so – standalone PKCS#11 module)
 *
 * Installation
 * ------------
 *   Option A – system-wide (requires root):
 *     sudo cp build/libstsafe_engine.so $(openssl version -e | grep ENGINESDIR | cut -d'"' -f2)/
 *
 *   Option B – any path: set dynamic_path in Engine/openssl-stsafe.cnf
 *
 * Configuration via openssl.cnf
 * ------------------------------
 *   See Engine/openssl-stsafe.cnf for a ready-to-use template.
 *   Point OpenSSL at it with:
 *     export OPENSSL_CONF=/path/to/Engine/openssl-stsafe.cnf
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
 *   Compile with -DSTSAFE_USE_DYNAMIC_ENGINE:
 *     make tls_dynamic
 *   Then run with:
 *     OPENSSL_CONF=Engine/openssl-stsafe.cnf ./build/06_TLS_client_dynamic
 *
 * Known PKCS#11 layer limitations
 * --------------------------------
 *   See Engine/PKCS11_ISSUES.md for a detailed report.
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

/* STSELib PKCS#11 layer -------------------------------------------------- */
#include "sal/pkcs11/stse_pkcs11.h"

/* stse_conf.h is in the Engine/ directory (found via -I$(ENGINE_DIR)) */
#include "stse_conf.h"

/* -------------------------------------------------------------------------
 * Engine identity
 * ---------------------------------------------------------------------- */

#define STSAFE_ENGINE_ID   "stsafe"
#define STSAFE_ENGINE_NAME "STSAFE-A120 Hardware Engine (PKCS#11)"

/* -------------------------------------------------------------------------
 * Module-level state
 * ---------------------------------------------------------------------- */

/** PKCS#11 session handle opened during ENGINE_init() */
static CK_SESSION_HANDLE g_pkcs11_session    = CK_INVALID_HANDLE;
static int               g_pkcs11_initialized = 0;

/* Runtime-configurable parameters – set via ctrl commands or openssl.cnf */
static uint8_t  g_i2c_bus   = 1;
static uint16_t g_i2c_speed = 400;
static uint8_t  g_cert_zone = 0;    /* index into configured cert_zone_indices */
static uint8_t  g_key_slot  = 0;

/** Custom EC_KEY_METHOD that overrides sign_sig */
static EC_KEY_METHOD *g_stsafe_ec_method = NULL;

/** ex_data index on EC_KEY objects to hold the PKCS#11 signing context */
static int g_ec_key_ctx_idx = -1;

/* -------------------------------------------------------------------------
 * Internal types
 * ---------------------------------------------------------------------- */

/** Context stored in EC_KEY ex_data for each STSAFE-backed key. */
typedef struct stsafe_ec_key_ctx {
    CK_OBJECT_HANDLE privkey_handle; /**< PKCS#11 handle of the private key  */
    stse_ecc_key_type_t key_type;    /**< ECC curve type (for buffer sizing)  */
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
        "STSAFE data zone index for the DER leaf certificate (default: 0)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_KEY_SLOT, "KEY_SLOT",
        "STSAFE private key slot for ECDSA signing (default: 0)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_LOAD_CERT, "LOAD_CERT",
        "Load X509 from STSAFE data zone i into *p (X509 **); internal use",
        ENGINE_CMD_FLAG_INTERNAL
    },
    { 0, NULL, NULL, 0 }  /* terminator */
};

/* -------------------------------------------------------------------------
 * Internal helper: PKCS#11 session management
 * ---------------------------------------------------------------------- */

/**
 * @brief  Return the currently open PKCS#11 session, or open a new one.
 * @return A valid CK_SESSION_HANDLE, or CK_INVALID_HANDLE on error.
 */
static CK_SESSION_HANDLE stsafe_pkcs11_session(void)
{
    CK_RV rv;

    if (g_pkcs11_session != CK_INVALID_HANDLE) {
        return g_pkcs11_session;
    }

    /* Open a read-only session on slot 0 */
    rv = C_OpenSession(0UL,
                       CKF_SERIAL_SESSION,  /* read-only session */
                       NULL, NULL,
                       &g_pkcs11_session);
    if (rv != CKR_OK) {
        fprintf(stderr,
                "stsafe_engine_so: C_OpenSession failed (0x%08lX)\n",
                (unsigned long)rv);
        g_pkcs11_session = CK_INVALID_HANDLE;
    }
    return g_pkcs11_session;
}

/* -------------------------------------------------------------------------
 * Internal helper: load certificate from a STSAFE data zone via PKCS#11
 * ---------------------------------------------------------------------- */

/**
 * @brief  Read a DER certificate from a STSAFE data zone via PKCS#11 and
 *         decode it as an X509 object.
 *
 * Uses the two-pass PKCS#11 pattern:
 *   1. C_GetAttributeValue with pValue=NULL to query the certificate size.
 *   2. Allocate buffer.
 *   3. C_GetAttributeValue again with the buffer to retrieve the DER bytes.
 *
 * @param  zone_index  Index into the engine's configured cert_zone_indices
 *                     array.  Corresponds to the PKCS#11 certificate object
 *                     handle STSE_PKCS11_CERT_HANDLE(zone_index).
 * @return Allocated X509 or NULL on error.  Caller must call X509_free().
 */
static X509 *stsafe_pkcs11_load_cert(uint8_t zone_index)
{
    CK_SESSION_HANDLE session;
    CK_RV             rv;
    X509             *cert = NULL;

    session = stsafe_pkcs11_session();
    if (session == CK_INVALID_HANDLE) {
        return NULL;
    }

    CK_OBJECT_HANDLE cert_handle = STSE_PKCS11_CERT_HANDLE(zone_index);

    /* Phase 1: query the DER length */
    CK_ATTRIBUTE attr_len = { CKA_VALUE, NULL, 0UL };
    rv = C_GetAttributeValue(session, cert_handle, &attr_len, 1UL);
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        fprintf(stderr,
                "stsafe_engine_so: C_GetAttributeValue(CKA_VALUE, len) "
                "failed (0x%08lX) for zone %u\n",
                (unsigned long)rv, (unsigned int)zone_index);
        return NULL;
    }

    CK_ULONG cert_len = attr_len.ulValueLen;
    /* CK_UNAVAILABLE_INFORMATION is (CK_ULONG)(-1) per PKCS#11 spec */
    if (cert_len == 0UL || cert_len == ~0UL) {
        fprintf(stderr,
                "stsafe_engine_so: certificate in zone %u reports invalid "
                "length %lu\n",
                (unsigned int)zone_index, (unsigned long)cert_len);
        return NULL;
    }

    /* Phase 2: retrieve the DER bytes */
    uint8_t *der_buf = (uint8_t *)malloc((size_t)cert_len);
    if (der_buf == NULL) {
        fprintf(stderr, "stsafe_engine_so: out of memory for cert DER\n");
        return NULL;
    }

    CK_ATTRIBUTE attr_val = { CKA_VALUE, der_buf, cert_len };
    rv = C_GetAttributeValue(session, cert_handle, &attr_val, 1UL);
    if (rv != CKR_OK) {
        fprintf(stderr,
                "stsafe_engine_so: C_GetAttributeValue(CKA_VALUE, buf) "
                "failed (0x%08lX)\n", (unsigned long)rv);
        free(der_buf);
        return NULL;
    }

    /* Decode DER */
    const uint8_t *p = der_buf;
    cert = d2i_X509(NULL, &p, (long)attr_val.ulValueLen);
    free(der_buf);

    if (cert == NULL) {
        fprintf(stderr,
                "stsafe_engine_so: d2i_X509 failed for zone %u\n",
                (unsigned int)zone_index);
    }
    return cert;
}

/* -------------------------------------------------------------------------
 * Internal helper: detect key type for a PKCS#11 private-key slot
 * ---------------------------------------------------------------------- */

/**
 * @brief  Query the PKCS#11 CKA_EC_PARAMS attribute of a public key and map
 *         the DER OID to a stse_ecc_key_type_t.
 *
 * Falls back to STSE_ECC_KT_NIST_P_256 when the curve cannot be identified,
 * which is safe because P-256 is the only curve supported by STSAFE-A120.
 */
static stse_ecc_key_type_t stsafe_detect_key_type(uint8_t slot)
{
    CK_SESSION_HANDLE session = stsafe_pkcs11_session();
    if (session == CK_INVALID_HANDLE) {
        return STSE_ECC_KT_NIST_P_256;
    }

    uint8_t ec_params[STSE_PKCS11_MAX_EC_PARAMS_SIZE];
    CK_ATTRIBUTE attr = { CKA_EC_PARAMS, ec_params, sizeof(ec_params) };

    CK_OBJECT_HANDLE pubkey_handle = STSE_PKCS11_PUBKEY_HANDLE(slot);
    CK_RV rv = C_GetAttributeValue(session, pubkey_handle, &attr, 1UL);
    if (rv != CKR_OK || attr.ulValueLen < 2UL) {
        return STSE_ECC_KT_NIST_P_256;  /* fallback */
    }

    /* The EC params is a DER-encoded OID: 0x06 <len> <bytes...> */
    uint8_t oid_len = ec_params[1];
    stse_ecc_key_type_t kt = STSE_ECC_KT_NIST_P_256;
    (void)stse_get_ecc_key_type_from_curve_id(oid_len, &ec_params[2], &kt);
    return kt;
}

/* -------------------------------------------------------------------------
 * Internal helper: create engine-backed EVP_PKEY
 * ---------------------------------------------------------------------- */

/**
 * @brief  Build an EVP_PKEY that routes ECDSA signing to a STSAFE slot.
 * @param  e            ENGINE handle.
 * @param  slot         STSAFE private key slot number.
 * @param  key_type     ECC curve type (for signature buffer sizing).
 * @param  pub_ec_key   EC_KEY carrying the public point to copy.
 * @return Newly allocated EVP_PKEY, or NULL on error.
 */
static EVP_PKEY *stsafe_so_create_engine_key(ENGINE              *e,
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
        return NULL;
    }

    const EC_GROUP *group = EC_KEY_get0_group(pub_ec_key);
    if (EC_KEY_set_group(ec_key, group) != 1) {
        EC_KEY_free(ec_key);
        return NULL;
    }

    const EC_POINT *pub_pt = EC_KEY_get0_public_key(pub_ec_key);
    if (EC_KEY_set_public_key(ec_key, pub_pt) != 1) {
        EC_KEY_free(ec_key);
        return NULL;
    }

    stsafe_ec_key_ctx_t *ctx =
        (stsafe_ec_key_ctx_t *)calloc(1, sizeof(stsafe_ec_key_ctx_t));
    if (ctx == NULL) {
        EC_KEY_free(ec_key);
        return NULL;
    }
    ctx->privkey_handle = STSE_PKCS11_PRIVKEY_HANDLE(slot);
    ctx->key_type       = key_type;

    if (EC_KEY_set_ex_data(ec_key, g_ec_key_ctx_idx, ctx) != 1) {
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
 * ECDSA sign_sig callback (uses PKCS#11 C_Sign with CKM_ECDSA)
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
        fprintf(stderr, "stsafe_engine_so: no PKCS#11 context on EC_KEY\n");
        return NULL;
    }

    if (dgst == NULL || dgst_len <= 0) {
        fprintf(stderr, "stsafe_engine_so: invalid digest\n");
        return NULL;
    }

    CK_SESSION_HANDLE session = stsafe_pkcs11_session();
    if (session == CK_INVALID_HANDLE) {
        fprintf(stderr, "stsafe_engine_so: no open PKCS#11 session\n");
        return NULL;
    }

    /* Use CKM_ECDSA: OpenSSL pre-hashes; we sign the raw digest */
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0UL };
    CK_RV rv = C_SignInit(session, &mech, ctx->privkey_handle);
    if (rv != CKR_OK) {
        fprintf(stderr,
                "stsafe_engine_so: C_SignInit failed (0x%08lX)\n",
                (unsigned long)rv);
        return NULL;
    }

    uint16_t sig_size = stse_ecc_info_table[ctx->key_type].signature_size;
    if (sig_size == 0U) {
        fprintf(stderr, "stsafe_engine_so: unknown signature size\n");
        return NULL;
    }
    uint16_t coord_size = sig_size / 2U;

    uint8_t *raw_sig = (uint8_t *)calloc(1, sig_size);
    if (raw_sig == NULL) {
        fprintf(stderr, "stsafe_engine_so: OOM for signature buffer\n");
        return NULL;
    }

    CK_ULONG out_sig_len = sig_size;
    rv = C_Sign(session,
                (CK_BYTE_PTR)(uintptr_t)dgst, (CK_ULONG)dgst_len,
                raw_sig, &out_sig_len);
    if (rv != CKR_OK) {
        fprintf(stderr,
                "stsafe_engine_so: C_Sign failed (0x%08lX)\n",
                (unsigned long)rv);
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
    CK_RV rv;
    (void)e;

    if (g_pkcs11_initialized) {
        return 1;  /* idempotent */
    }

    /* Configure the PKCS#11 token with the user-supplied parameters */
    stse_pkcs11_config_t cfg = {
        .i2c_addr        = 0x20U,            /* STSAFE-A120 default 7-bit I2C address */
        .bus_id          = g_i2c_bus,
        .bus_speed       = g_i2c_speed,
        .device_type     = STSAFE_A120,
        .cert_zone_count = 1U,
        .cert_zone_indices = { g_cert_zone }  /* zone that holds the leaf certificate */
    };
    stse_pkcs11_set_config(&cfg);

    rv = C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        fprintf(stderr,
                "stsafe_engine_so: C_Initialize failed (0x%08lX) "
                "[i2c=%u speed=%u]\n",
                (unsigned long)rv,
                (unsigned int)g_i2c_bus,
                (unsigned int)g_i2c_speed);
        return 0;
    }

    g_pkcs11_initialized = 1;

    /* Pre-open a session so sign_sig does not need to open one per call */
    if (stsafe_pkcs11_session() == CK_INVALID_HANDLE) {
        fprintf(stderr, "stsafe_engine_so: could not open PKCS#11 session\n");
        C_Finalize(NULL);
        g_pkcs11_initialized = 0;
        return 0;
    }

    fprintf(stderr,
            "stsafe_engine_so: PKCS#11 token initialised on /dev/i2c-%u "
            "at %u kHz\n",
            (unsigned int)g_i2c_bus, (unsigned int)g_i2c_speed);
    return 1;
}

static int stsafe_so_finish(ENGINE *e)
{
    (void)e;
    if (g_pkcs11_session != CK_INVALID_HANDLE) {
        C_CloseSession(g_pkcs11_session);
        g_pkcs11_session = CK_INVALID_HANDLE;
    }
    if (g_pkcs11_initialized) {
        C_Finalize(NULL);
        g_pkcs11_initialized = 0;
    }
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
 * Handles numeric config commands (from openssl.cnf / ENGINE_ctrl_cmd())
 * and the internal LOAD_CERT command.
 *
 * openssl.cnf string values are auto-converted to longs for numeric commands.
 * The LOAD_CERT command uses:
 *   i = cert zone index (into cfg.cert_zone_indices)
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
        *out = stsafe_pkcs11_load_cert((uint8_t)i);
        return (*out != NULL) ? 1 : 0;
    }

    default:
        return 0;
    }
}

/**
 * @brief  ENGINE load_privkey callback.
 *
 * Called when an application requests a private key from this engine:
 *   ENGINE_load_private_key(e, key_id, NULL, NULL)
 *   openssl s_client -engine stsafe -keyform ENGINE -key "0"
 *
 * The function:
 *  1. Parses the key_id string (format: "N" or "N:Z").
 *  2. Detects the ECC curve of the slot via PKCS#11.
 *  3. Loads the public point from the device certificate (zone Z).
 *  4. Returns an engine-backed EVP_PKEY wrapping the public point.
 *
 * @param  key_id  Key identifier: "N" (slot N, default zone) or "N:Z"
 *                 (slot N, cert zone Z).
 */
static EVP_PKEY *stsafe_so_load_privkey(ENGINE      *e,
                                         const char  *key_id,
                                         UI_METHOD   *ui,
                                         void        *cb_data)
{
    (void)ui;
    (void)cb_data;

    /* Parse key_id.
     *
     * cert_zone_index is an index into the engine's stse_pkcs11_config_t
     * cert_zone_indices[] array (configured in stsafe_so_init).  The index 0
     * maps to the STSAFE data zone stored in cfg.cert_zone_indices[0], which
     * defaults to the zone number set via the CERT_ZONE ctrl command.
     *
     * Accepted formats:
     *   "N"    – private key slot N, certificate from cert_zone_index 0
     *   "N:Z"  – private key slot N, certificate from cert_zone_index Z
     */
    uint8_t slot           = g_key_slot;
    uint8_t cert_zone_index = 0U;   /* index into cfg.cert_zone_indices[] */

    if (key_id != NULL && key_id[0] != '\0') {
        const char *colon = strchr(key_id, ':');
        if (colon != NULL) {
            slot            = (uint8_t)atoi(key_id);
            cert_zone_index = (uint8_t)atoi(colon + 1);
        } else {
            slot = (uint8_t)atoi(key_id);
        }
    }

    /* Detect the ECC curve for this private-key slot */
    stse_ecc_key_type_t key_type = stsafe_detect_key_type(slot);

    /* Load the certificate from cert_zone_index to obtain the public key */
    X509 *cert = stsafe_pkcs11_load_cert(cert_zone_index);
    if (cert == NULL) {
        fprintf(stderr,
                "stsafe_engine_so: load_privkey: cert load "
                "(cert_zone_index=%u) failed\n",
                (unsigned int)cert_zone_index);
        return NULL;
    }

    EVP_PKEY *cert_pub = X509_get0_pubkey(cert);
    if (cert_pub == NULL || EVP_PKEY_id(cert_pub) != EVP_PKEY_EC) {
        fprintf(stderr,
                "stsafe_engine_so: load_privkey: cert at zone_index %u "
                "has no EC key\n",
                (unsigned int)cert_zone_index);
        X509_free(cert);
        return NULL;
    }

    EC_KEY *pub_ec_key = (EC_KEY *)(uintptr_t)EVP_PKEY_get0_EC_KEY(cert_pub);
    EVP_PKEY *pkey = stsafe_so_create_engine_key(e, slot, key_type, pub_ec_key);
    X509_free(cert);

    if (pkey == NULL) {
        fprintf(stderr,
                "stsafe_engine_so: load_privkey: key creation (slot %u) "
                "failed\n", (unsigned int)slot);
    } else {
        fprintf(stderr,
                "stsafe_engine_so: PKCS#11 private key loaded "
                "(slot %u, cert_zone_index %u)\n",
                (unsigned int)slot, (unsigned int)cert_zone_index);
    }

    return pkey;
}

/* -------------------------------------------------------------------------
 * EC_KEY_METHOD setup
 * ---------------------------------------------------------------------- */

static int stsafe_so_setup_ec_method(void)
{
    if (g_ec_key_ctx_idx == -1) {
        g_ec_key_ctx_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (g_ec_key_ctx_idx < 0) {
            return 0;
        }
    }

    if (g_stsafe_ec_method == NULL) {
        g_stsafe_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
        if (g_stsafe_ec_method == NULL) {
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
 * Called by the OpenSSL dynamic loader immediately after dlopen().
 */
static int stsafe_so_bind(ENGINE *e, const char *id)
{
    if (id != NULL && strcmp(id, STSAFE_ENGINE_ID) != 0) {
        return 0;
    }

    if (!stsafe_so_setup_ec_method()) {
        return 0;
    }

    if (!ENGINE_set_id(e, STSAFE_ENGINE_ID))                         return 0;
    if (!ENGINE_set_name(e, STSAFE_ENGINE_NAME))                     return 0;
    if (!ENGINE_set_init_function(e,    stsafe_so_init))             return 0;
    if (!ENGINE_set_finish_function(e,  stsafe_so_finish))           return 0;
    if (!ENGINE_set_destroy_function(e, stsafe_so_destroy))          return 0;
    if (!ENGINE_set_ctrl_function(e,    stsafe_so_ctrl))             return 0;
    if (!ENGINE_set_cmd_defns(e,        g_cmd_defns))                return 0;
    if (!ENGINE_set_EC(e,               g_stsafe_ec_method))         return 0;
    if (!ENGINE_set_load_privkey_function(e, stsafe_so_load_privkey)) return 0;

    return 1;
}

/* -------------------------------------------------------------------------
 * Dynamic loader entry points (must be exported symbols)
 * ---------------------------------------------------------------------- */

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(stsafe_so_bind)

