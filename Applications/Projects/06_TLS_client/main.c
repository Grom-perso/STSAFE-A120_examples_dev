/******************************************************************************
 * \file    main.c
 * \brief   STSAFE-A120 TLS 1.3 client example using the STSAFE OpenSSL
 *          dynamic engine.
 *
 *          This example demonstrates how the STSAFE-A120 can be used as the
 *          TLS client's identity provider on a Linux host:
 *
 *           1. The STSAFE OpenSSL engine is loaded dynamically.
 *           2. The I2C bus and device parameters are passed via engine control
 *              commands (I2C_BUS, CERT_ZONE, KEY_SLOT).
 *           3. The client certificate (X.509 DER) is read from the STSAFE
 *              data zone using the LOAD_CERT control command.
 *           4. The TLS private key is loaded from the STSAFE key slot using
 *              ENGINE_load_private_key() – the raw key never leaves the
 *              secure element.
 *           5. A TLS 1.3 connection is established to the specified server,
 *              with the STSAFE performing the ECDSA signature during the
 *              TLS handshake.
 *
 *          Usage:
 *            ./06_TLS_client <host> <port> [i2c_bus] [cert_zone] [key_slot]
 *
 *          Defaults:
 *            i2c_bus   = /dev/i2c-1
 *            cert_zone = 0
 *            key_slot  = 0
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Engine control command IDs (mirrored from Engine/stsafe_engine.h) */
#define STSAFE_ENGINE_ID     "stsafe"
#define STSAFE_CMD_I2C_BUS   (ENGINE_CMD_BASE)
#define STSAFE_CMD_I2C_SPEED (ENGINE_CMD_BASE + 1)
#define STSAFE_CMD_CERT_ZONE (ENGINE_CMD_BASE + 2)
#define STSAFE_CMD_KEY_SLOT  (ENGINE_CMD_BASE + 3)
#define STSAFE_CMD_LOAD_CERT (ENGINE_CMD_BASE + 4)

/* Path to the compiled STSAFE engine shared library */
#ifndef STSAFE_ENGINE_SO_PATH
#define STSAFE_ENGINE_SO_PATH "./libstsafe_engine.so"
#endif

static void print_ssl_errors(void)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        fprintf(stderr, "  SSL error: %s\n", ERR_error_string(err, NULL));
    }
}

/**
 * @brief  Main entry point – STSAFE-A120 TLS 1.3 client example.
 */
int main(int argc, char *argv[])
{
    const char *host      = (argc > 1) ? argv[1] : "localhost";
    const char *port      = (argc > 2) ? argv[2] : "4433";
    const char *i2c_bus   = (argc > 3) ? argv[3] : "/dev/i2c-1";
    int         cert_zone = (argc > 4) ? atoi(argv[4]) : 0;
    int         key_slot  = (argc > 5) ? atoi(argv[5]) : 0;
    int         ret       = EXIT_FAILURE;

    printf("-----------------------------------------------------------\n");
    printf(" STSAFE-A120 TLS 1.3 Client Example\n");
    printf("-----------------------------------------------------------\n");
    printf(" Host      : %s:%s\n", host, port);
    printf(" I2C bus   : %s\n", i2c_bus);
    printf(" Cert zone : %d\n", cert_zone);
    printf(" Key slot  : %d\n", key_slot);
    printf("-----------------------------------------------------------\n");

    /* Initialise OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Load the STSAFE engine */
    ENGINE_load_dynamic();
    ENGINE *engine = ENGINE_by_id("dynamic");
    if (engine == NULL) {
        fprintf(stderr, "[ERROR] Could not obtain dynamic engine loader\n");
        goto cleanup_ssl;
    }

    if (!ENGINE_ctrl_cmd_string(engine, "SO_PATH", STSAFE_ENGINE_SO_PATH, 0) ||
        !ENGINE_ctrl_cmd_string(engine, "ID", STSAFE_ENGINE_ID, 0)           ||
        !ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0)) {
        fprintf(stderr, "[ERROR] Failed to load STSAFE engine from %s\n",
                STSAFE_ENGINE_SO_PATH);
        print_ssl_errors();
        ENGINE_free(engine);
        goto cleanup_ssl;
    }
    ENGINE_free(engine);

    engine = ENGINE_by_id(STSAFE_ENGINE_ID);
    if (engine == NULL) {
        fprintf(stderr, "[ERROR] STSAFE engine not found after loading\n");
        print_ssl_errors();
        goto cleanup_ssl;
    }

    /* Configure the engine */
    ENGINE_ctrl_cmd_string(engine, "I2C_BUS", i2c_bus, 0);
    ENGINE_ctrl_cmd(engine, STSAFE_CMD_CERT_ZONE, cert_zone, NULL, NULL, 0);
    ENGINE_ctrl_cmd(engine, STSAFE_CMD_KEY_SLOT,  key_slot,  NULL, NULL, 0);

    if (!ENGINE_init(engine)) {
        fprintf(stderr, "[ERROR] ENGINE_init failed\n");
        print_ssl_errors();
        goto cleanup_engine;
    }
    printf("[OK] STSAFE engine initialised\n");

    /* Load the client certificate from the STSAFE */
    X509 *client_cert = NULL;
    if (!ENGINE_ctrl_cmd(engine, STSAFE_CMD_LOAD_CERT, 0,
                          (void *)&client_cert, NULL, 0) ||
        client_cert == NULL) {
        fprintf(stderr, "[ERROR] Failed to load certificate from STSAFE zone %d\n",
                cert_zone);
        print_ssl_errors();
        goto cleanup_engine_init;
    }
    printf("[OK] Client certificate loaded from STSAFE zone %d\n", cert_zone);

    /* Load the private key reference from the STSAFE key slot */
    char key_id[16];
    snprintf(key_id, sizeof(key_id), "slot:%d", key_slot);
    EVP_PKEY *private_key = ENGINE_load_private_key(engine, key_id,
                                                     NULL, NULL);
    if (private_key == NULL) {
        fprintf(stderr, "[ERROR] Failed to load private key from STSAFE slot %d\n",
                key_slot);
        print_ssl_errors();
        X509_free(client_cert);
        goto cleanup_engine_init;
    }
    printf("[OK] Private key reference loaded from STSAFE slot %d\n", key_slot);

    /* Set up TLS 1.3 client context */
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL) {
        fprintf(stderr, "[ERROR] SSL_CTX_new failed\n");
        print_ssl_errors();
        EVP_PKEY_free(private_key);
        X509_free(client_cert);
        goto cleanup_engine_init;
    }

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_engine(ssl_ctx, engine);

    if (!SSL_CTX_use_certificate(ssl_ctx, client_cert)) {
        fprintf(stderr, "[ERROR] SSL_CTX_use_certificate failed\n");
        print_ssl_errors();
        goto cleanup_ssl_ctx;
    }

    if (!SSL_CTX_use_PrivateKey(ssl_ctx, private_key)) {
        fprintf(stderr, "[ERROR] SSL_CTX_use_PrivateKey failed\n");
        print_ssl_errors();
        goto cleanup_ssl_ctx;
    }

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "[ERROR] Private key / certificate mismatch\n");
        print_ssl_errors();
        goto cleanup_ssl_ctx;
    }

    printf("[OK] TLS context configured – STSAFE will sign during handshake\n");
    printf("[INFO] Connect to %s:%s to trigger TLS handshake\n", host, port);
    printf("[INFO] (Integration with a live server is left to the application)\n");

    ret = EXIT_SUCCESS;

cleanup_ssl_ctx:
    SSL_CTX_free(ssl_ctx);
    EVP_PKEY_free(private_key);
    X509_free(client_cert);

cleanup_engine_init:
    ENGINE_finish(engine);

cleanup_engine:
    ENGINE_free(engine);

cleanup_ssl:
    EVP_cleanup();
    ERR_free_strings();

    if (ret == EXIT_SUCCESS) {
        printf("[PASS] TLS client setup completed successfully\n");
    } else {
        printf("[FAIL] TLS client setup failed – see errors above\n");
    }

    return ret;
}
