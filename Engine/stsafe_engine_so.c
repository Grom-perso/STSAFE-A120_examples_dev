/******************************************************************************
 * \file    stsafe_engine_so.c
 * \brief   STSAFE-A OpenSSL dynamic engine implementation.
 *
 *          Builds as a shared library (libstsafe_engine.so) that OpenSSL
 *          can load at runtime via ENGINE_by_id("stsafe") or
 *          ENGINE_load_dynamic().
 *
 *          The engine:
 *           - Opens the Linux I2C bus specified by the I2C_BUS ctrl command.
 *           - Initialises the STSAFE-A handler using the portable platform
 *             layer (Platform_Portable/).
 *           - Overrides EC_KEY_METHOD to route ECDSA sign operations to the
 *             STSAFE private key stored in the configured key slot.
 *           - Provides a LOAD_CERT ctrl command to read a DER certificate
 *             from a STSAFE data zone and return it as an X509 object.
 *
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2024 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include "stsafe_engine.h"
#include "Platform_Portable/stse_platform_portable.h"
#include "stselib.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/** Size in bytes of one ECDSA-P256 integer component (r or s). */
#define ECDSA_P256_COMPONENT_SIZE 32U

/* --------------------------------------------------------------------------
 * Engine state
 * -------------------------------------------------------------------------- */

typedef struct {
    stse_Handler_t stse;
    int            i2c_fd;
    uint8_t        i2c_addr;
    char           i2c_bus[64];
    int            i2c_speed_khz;
    uint8_t        cert_zone;
    uint8_t        key_slot;
    int            initialized;
} stsafe_engine_ctx_t;

static stsafe_engine_ctx_t g_ctx = {
    .i2c_fd       = -1,
    .i2c_addr     = 0x20,
    .i2c_speed_khz = 400,
    .cert_zone    = 0,
    .key_slot     = 0,
    .initialized  = 0,
};

/* ex_data index used to attach the engine context to EC_KEY objects */
static int g_ec_key_ctx_idx = -1;

/* --------------------------------------------------------------------------
 * Linux I2C platform callbacks (registered via stse_platform_set_io)
 * -------------------------------------------------------------------------- */

static int linux_i2c_write(uint8_t dev_addr, const uint8_t *p_data,
                            uint16_t length)
{
    if (g_ctx.i2c_fd < 0) {
        return -1;
    }
    if (ioctl(g_ctx.i2c_fd, I2C_SLAVE, dev_addr) < 0) {
        return -1;
    }
    if (length == 0) {
        return 0; /* wake pulse */
    }
    return (write(g_ctx.i2c_fd, p_data, length) == length) ? 0 : -1;
}

static int linux_i2c_read(uint8_t dev_addr, uint8_t *p_data, uint16_t length)
{
    if (g_ctx.i2c_fd < 0) {
        return -1;
    }
    if (ioctl(g_ctx.i2c_fd, I2C_SLAVE, dev_addr) < 0) {
        return -1;
    }
    return (read(g_ctx.i2c_fd, p_data, length) == length) ? 0 : -1;
}

static void linux_delay_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000UL;
    ts.tv_nsec = (ms % 1000UL) * 1000000L;
    nanosleep(&ts, NULL);
}

/* --------------------------------------------------------------------------
 * Engine initialisation / deinitialisation
 * -------------------------------------------------------------------------- */

static int stsafe_engine_init(ENGINE *e)
{
    (void)e;
    stse_portable_io_t io = {
        .i2c_read  = linux_i2c_read,
        .i2c_write = linux_i2c_write,
        .delay_ms  = linux_delay_ms,
        .rng       = NULL,
    };
    stse_ReturnCode_t ret;

    if (g_ctx.initialized) {
        return 1;
    }

    /* Open I2C bus */
    g_ctx.i2c_fd = open(g_ctx.i2c_bus[0] ? g_ctx.i2c_bus : "/dev/i2c-1",
                        O_RDWR);
    if (g_ctx.i2c_fd < 0) {
        ENGINEerr(ENGINE_F_ENGINE_INIT, ENGINE_R_INIT_FAILED);
        return 0;
    }

    /* Register portable I/O */
    if (stse_platform_set_io(&io) != 0) {
        close(g_ctx.i2c_fd);
        g_ctx.i2c_fd = -1;
        return 0;
    }

    /* Initialise STSAFE handler */
    stse_set_default_handler_value(&g_ctx.stse);
    g_ctx.stse.device_type  = STSAFE_A120;
    g_ctx.stse.io.busID     = 1;
    g_ctx.stse.io.BusSpeed  = (uint16_t)g_ctx.i2c_speed_khz;

    ret = stse_init(&g_ctx.stse);
    if (ret != STSE_OK) {
        close(g_ctx.i2c_fd);
        g_ctx.i2c_fd = -1;
        ENGINEerr(ENGINE_F_ENGINE_INIT, ENGINE_R_INIT_FAILED);
        return 0;
    }

    g_ctx.initialized = 1;
    return 1;
}

static int stsafe_engine_finish(ENGINE *e)
{
    (void)e;
    if (g_ctx.i2c_fd >= 0) {
        close(g_ctx.i2c_fd);
        g_ctx.i2c_fd = -1;
    }
    g_ctx.initialized = 0;
    return 1;
}

/* --------------------------------------------------------------------------
 * EC_KEY sign override
 * -------------------------------------------------------------------------- */

typedef struct {
    stse_Handler_t *pSTSE;
    uint8_t         key_slot;
} stsafe_ec_key_ctx_t;

static EC_KEY_METHOD *g_stsafe_ec_method = NULL;

/**
 * @brief  sign_sig callback for EC_KEY_METHOD.
 *
 * Returns an ECDSA_SIG* built from the raw (r || s) output of the STSAFE
 * ECDSA command.  This function matches the sign_sig slot of
 * EC_KEY_METHOD_set_sign() which expects:
 *   ECDSA_SIG *(*)(const unsigned char *dgst, int dgst_len,
 *                  const BIGNUM *in_kinv, const BIGNUM *in_r,
 *                  EC_KEY *eckey)
 */
static ECDSA_SIG *stsafe_ecdsa_sign_sig(const unsigned char *dgst,
                                         int dgst_len,
                                         const BIGNUM *in_kinv,
                                         const BIGNUM *in_r,
                                         EC_KEY *eckey)
{
    (void)in_kinv;
    (void)in_r;

    stsafe_ec_key_ctx_t *ctx =
        (stsafe_ec_key_ctx_t *)EC_KEY_get_ex_data(eckey, g_ec_key_ctx_idx);
    if (ctx == NULL) {
        return NULL;
    }

    uint8_t  raw_sig[ECDSA_P256_COMPONENT_SIZE * 2U];
    uint16_t raw_sig_len = sizeof(raw_sig);

    stse_ReturnCode_t ret =
        stse_ecc_generate_signature(ctx->pSTSE,
                                    ctx->key_slot,
                                    STSE_ECC_KT_NIST_P_256,
                                    STSE_SHA_256,
                                    dgst,
                                    (uint16_t)dgst_len,
                                    raw_sig,
                                    &raw_sig_len);
    if (ret != STSE_OK) {
        return NULL;
    }

    /* Build and return an ECDSA_SIG from the raw (r || s) bytes */
    BIGNUM *r = BN_bin2bn(raw_sig,                          ECDSA_P256_COMPONENT_SIZE, NULL);
    BIGNUM *s = BN_bin2bn(raw_sig + ECDSA_P256_COMPONENT_SIZE, ECDSA_P256_COMPONENT_SIZE, NULL);
    if (r == NULL || s == NULL) {
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == NULL) {
        BN_free(r);
        BN_free(s);
        return NULL;
    }
    ECDSA_SIG_set0(sig, r, s);
    return sig;
}

/* --------------------------------------------------------------------------
 * ENGINE_load_private_key: key_id = "slot:<N>"
 * -------------------------------------------------------------------------- */

static EVP_PKEY *stsafe_load_privkey(ENGINE *e, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data)
{
    (void)e;
    (void)ui_method;
    (void)callback_data;

    uint8_t slot = 0;
    if (strncmp(key_id, "slot:", 5) == 0) {
        slot = (uint8_t)atoi(key_id + 5);
    }

    /* Create an EC_KEY with the P-256 public key from the STSAFE */
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) {
        return NULL;
    }

    EC_KEY_set_method(eckey, g_stsafe_ec_method);

    /* Attach STSAFE context so the sign callback can reach the device */
    stsafe_ec_key_ctx_t *ctx =
        (stsafe_ec_key_ctx_t *)malloc(sizeof(stsafe_ec_key_ctx_t));
    if (ctx == NULL) {
        EC_KEY_free(eckey);
        return NULL;
    }
    ctx->pSTSE    = &g_ctx.stse;
    ctx->key_slot = slot;
    EC_KEY_set_ex_data(eckey, g_ec_key_ctx_idx, ctx);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        free(ctx);
        EC_KEY_free(eckey);
        return NULL;
    }
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    return pkey;
}

/* --------------------------------------------------------------------------
 * LOAD_CERT ctrl command
 * -------------------------------------------------------------------------- */

static int stsafe_load_cert(X509 **pp_cert, uint8_t zone)
{
    uint8_t  der_buf[1024];
    uint16_t der_len = sizeof(der_buf);

    stse_ReturnCode_t ret =
        stse_data_storage_read_data_zone(&g_ctx.stse, zone, 0,
                                         der_buf, der_len, 0);
    if (ret != STSE_OK) {
        return 0;
    }

    /* Determine actual DER length from the ASN.1 SEQUENCE header */
    if (der_buf[0] != 0x30) {
        return 0;
    }
    if (der_buf[1] & 0x80U) {
        uint8_t nb = der_buf[1] & 0x7FU;
        if (nb == 1) {
            der_len = (uint16_t)(der_buf[2] + 3U);
        } else if (nb == 2) {
            der_len = (uint16_t)(((uint16_t)der_buf[2] << 8) | der_buf[3]) + 4U;
        } else {
            return 0;
        }
    } else {
        der_len = (uint16_t)(der_buf[1] + 2U);
    }

    const unsigned char *p = der_buf;
    *pp_cert = d2i_X509(NULL, &p, der_len);
    return (*pp_cert != NULL) ? 1 : 0;
}

/* --------------------------------------------------------------------------
 * Engine ctrl command dispatcher
 * -------------------------------------------------------------------------- */

static int stsafe_ctrl(ENGINE *e, int cmd, long i, void *p,
                        void (*f)(void))
{
    (void)e;
    (void)f;

    switch (cmd) {
    case STSAFE_CMD_I2C_BUS:
        if (p == NULL) return 0;
        strncpy(g_ctx.i2c_bus, (const char *)p, sizeof(g_ctx.i2c_bus) - 1);
        g_ctx.i2c_bus[sizeof(g_ctx.i2c_bus) - 1] = '\0';
        return 1;

    case STSAFE_CMD_I2C_SPEED:
        g_ctx.i2c_speed_khz = (int)i;
        return 1;

    case STSAFE_CMD_CERT_ZONE:
        g_ctx.cert_zone = (uint8_t)i;
        return 1;

    case STSAFE_CMD_KEY_SLOT:
        g_ctx.key_slot = (uint8_t)i;
        return 1;

    case STSAFE_CMD_LOAD_CERT:
        if (p == NULL) return 0;
        return stsafe_load_cert((X509 **)p, g_ctx.cert_zone);

    default:
        ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED);
        return 0;
    }
}

/* --------------------------------------------------------------------------
 * Engine command descriptor table
 * -------------------------------------------------------------------------- */

static const ENGINE_CMD_DEFN stsafe_cmd_defns[] = {
    {STSAFE_CMD_I2C_BUS, "I2C_BUS",
     "Linux I2C bus device path (e.g. /dev/i2c-1)", ENGINE_CMD_FLAG_STRING},
    {STSAFE_CMD_I2C_SPEED, "I2C_SPEED",
     "I2C bus speed in kHz (default: 400)", ENGINE_CMD_FLAG_NUMERIC},
    {STSAFE_CMD_CERT_ZONE, "CERT_ZONE",
     "STSAFE data zone holding the certificate", ENGINE_CMD_FLAG_NUMERIC},
    {STSAFE_CMD_KEY_SLOT, "KEY_SLOT",
     "STSAFE key slot holding the private key", ENGINE_CMD_FLAG_NUMERIC},
    {STSAFE_CMD_LOAD_CERT, "LOAD_CERT",
     "Load X.509 cert from STSAFE zone into X509* (p = X509**)",
     ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}
};

/* --------------------------------------------------------------------------
 * bind_engine – called when the .so is loaded
 * -------------------------------------------------------------------------- */

int bind_engine(ENGINE *e, const char *id)
{
    if (id != NULL && strcmp(id, STSAFE_ENGINE_ID) != 0) {
        return 0;
    }

    /* Allocate EC_KEY method override for ECDSA sign.
     * We only override sign_sig (returns ECDSA_SIG*); sign and sign_setup
     * are left as NULL to inherit the OpenSSL defaults. */
    g_stsafe_ec_method = EC_KEY_METHOD_new(EC_KEY_get_default_method());
    if (g_stsafe_ec_method == NULL) {
        return 0;
    }
    EC_KEY_METHOD_set_sign(g_stsafe_ec_method,
                           NULL,                  /* sign (use default) */
                           NULL,                  /* sign_setup (use default) */
                           stsafe_ecdsa_sign_sig); /* sign_sig – our override */

    /* Reserve an ex_data slot for stsafe_ec_key_ctx_t* */
    g_ec_key_ctx_idx = EC_KEY_get_ex_new_index(0, "stsafe_ctx", NULL, NULL, NULL);

    if (!ENGINE_set_id(e, STSAFE_ENGINE_ID)              ||
        !ENGINE_set_name(e, STSAFE_ENGINE_NAME)          ||
        !ENGINE_set_init_function(e, stsafe_engine_init) ||
        !ENGINE_set_finish_function(e, stsafe_engine_finish) ||
        !ENGINE_set_load_privkey_function(e, stsafe_load_privkey) ||
        !ENGINE_set_ctrl_function(e, stsafe_ctrl)        ||
        !ENGINE_set_cmd_defns(e, stsafe_cmd_defns)) {
        return 0;
    }

    return 1;
}

/* Required symbol for OpenSSL dynamic engine loading */
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_engine)

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
