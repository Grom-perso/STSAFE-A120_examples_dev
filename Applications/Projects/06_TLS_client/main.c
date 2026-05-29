/**
 ******************************************************************************
 * @file    main.c
 * @author  CS application team
 * @brief   STSAFE-A120 TLS Client example using OpenSSL engine
 ******************************************************************************
 *           			COPYRIGHT 2022 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 *
 * Overview
 * --------
 * This example demonstrates how to integrate the STSAFE-A120 secure element
 * as a hardware key-store for TLS client authentication using OpenSSL.
 *
 * Key steps
 * ---------
 * 1. Initialise the STSAFE-A120 device handler via STSELib.
 * 2. Register the custom STSAFE OpenSSL engine.
 * 3. Load the device leaf certificate stored in STSAFE data zone 0.
 * 4. Create an EVP_PKEY whose private-key operations (ECDSA signing) are
 *    offloaded to the STSAFE-A120 – the private key never leaves the device.
 * 5. Configure an SSL_CTX with the certificate and engine-backed private key.
 * 6. Establish a TLS connection to the configured server.
 * 7. Optionally send an HTTP/1.1 GET request and print the response headers.
 *
 * When the TLS server requests a client certificate (mutual TLS), OpenSSL
 * calls the engine's ECDSA sign callback, which in turn calls
 * stse_ecc_generate_signature() inside the STSAFE-A120 over I2C.  The
 * private key is never exposed to the host processor.
 *
 * Configuration
 * -------------
 * See stse_conf.h for compile-time tunables:
 *   - STSAFE_I2C_BUS        I2C bus number (/dev/i2c-N)
 *   - STSAFE_CERT_ZONE      STSAFE data zone holding the leaf certificate
 *   - STSAFE_KEY_SLOT       STSAFE private key slot
 *   - TLS_SERVER_HOST       Target TLS server hostname
 *   - TLS_SERVER_PORT       Target TLS server port (default: "443")
 *   - TLS_CA_BUNDLE         Path to PEM CA trust bundle (NULL = system store)
 *
 */

/* Includes ------------------------------------------------------------------*/
#include "Apps_utils.h"
#include "stse_conf.h"

/* In static engine mode the application uses the stsafe_engine.h API
 * (stsafe_engine_get, stsafe_engine_load_cert, stsafe_engine_load_key).
 * In dynamic engine mode those symbols live in libstsafe_engine.so and are
 * accessed via the standard OpenSSL ENGINE_* API – no extra header needed. */
#ifndef STSAFE_USE_DYNAMIC_ENGINE
#  include "stsafe_engine.h"
#else
#  include <openssl/engine.h>
   /* Engine ID must match the value baked into the .so */
#  define STSAFE_ENGINE_ID "stsafe"
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Private defines -----------------------------------------------------------*/

/** Maximum number of bytes read from the server response */
#define TLS_READ_BUF_SIZE 4096U

/* Private function prototypes -----------------------------------------------*/
static int  tcp_connect(const char *host, const char *port);
static void print_openssl_errors(void);
static void print_cert_info(X509 *cert, const char *label);
static int  tls_send_http_get(SSL *ssl, const char *host, const char *path);
static void tls_print_response(SSL *ssl);

/* ---------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

/**
 * @brief  Main program entry point – STSAFE-A120 TLS Client example
 * @details
 *   1. Initialise STSAFE-A120 handler (static mode) or load engine from .so
 *      (dynamic mode).
 *   2. Register STSAFE OpenSSL engine.
 *   3. Load device certificate from STSAFE zone 0.
 *   4. Create engine-backed private key (signing done inside STSAFE).
 *   5. Set up SSL_CTX for mutual TLS.
 *   6. Establish TLS connection and perform HTTP GET.
 * @retval 0  Success
 * @retval 1  Failure (prints error to stderr)
 */
int main(void)
{
    int exit_code = 1;

    /* OpenSSL objects – initialised to NULL for safe cleanup */
    SSL_CTX  *ssl_ctx  = NULL;
    SSL      *ssl      = NULL;
    ENGINE   *engine   = NULL;
    X509     *dev_cert = NULL;
    EVP_PKEY *dev_key  = NULL;
    int       tcp_fd   = -1;

#ifndef STSAFE_USE_DYNAMIC_ENGINE
    /* STSELib objects – only needed in static engine mode */
    stse_Handler_t    stse_handler;
    stse_ReturnCode_t stse_ret;
#endif

    /* -----------------------------------------------------------------------
     * Banner
     * -------------------------------------------------------------------- */
    apps_terminal_init(115200);

    printf(PRINT_BOLD
           "\n\r=========================================================="
           "======================\n\r");
    printf("              STSAFE-A120 TLS Client Example (OpenSSL Engine)"
           "              \n\r");
    printf("==========================================================="
           "=====================" PRINT_RESET "\n\r\n\r");

    printf("Target server : %s:%s%s\n\r", TLS_SERVER_HOST, TLS_SERVER_PORT,
           TLS_SERVER_PATH);
    printf("STSAFE I2C bus: %d  |  Cert zone: %d  |  Key slot: %d\n\r\n\r",
           STSAFE_I2C_BUS, STSAFE_CERT_ZONE, STSAFE_KEY_SLOT);

    /* OpenSSL 1.1.1+ initialises itself; load built-in algorithms */
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

#ifdef STSAFE_USE_DYNAMIC_ENGINE
    /* =======================================================================
     * DYNAMIC ENGINE MODE
     * The engine shared library (libstsafe_engine.so) manages its own
     * stse_Handler_t.  No application-side I2C initialisation is needed.
     * ===================================================================== */

    /* -----------------------------------------------------------------------
     * Step 1 – Load the STSAFE engine from the shared library
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "## Step 1 – Load STSAFE dynamic engine\n\r" PRINT_RESET);

    /* First try: the engine may have been pre-loaded by OpenSSL via
     * OPENSSL_CONF pointing to Engine/openssl-stsafe.cnf */
    engine = ENGINE_by_id(STSAFE_ENGINE_ID);

    if (engine == NULL) {
        /* Second try: load the shared library explicitly via the built-in
         * 'dynamic' meta-engine */
        printf("   Engine not pre-loaded – loading from: %s\n\r",
               STSAFE_ENGINE_SO_PATH);

        ENGINE *loader = ENGINE_by_id("dynamic");
        if (loader == NULL) {
            printf(PRINT_RED
                   "   ERROR: ENGINE_by_id(\"dynamic\") failed – "
                   "is the dynamic engine loader available?\n\r" PRINT_RESET);
            print_openssl_errors();
            goto cleanup;
        }

        /* Point the dynamic loader at the .so */
        if (!ENGINE_ctrl_cmd_string(loader, "SO_PATH",
                                    STSAFE_ENGINE_SO_PATH, 0) ||
            !ENGINE_ctrl_cmd_string(loader, "LOAD", NULL, 0)) {
            printf(PRINT_RED
                   "   ERROR: failed to load engine from %s\n\r" PRINT_RESET,
                   STSAFE_ENGINE_SO_PATH);
            print_openssl_errors();
            ENGINE_free(loader);
            goto cleanup;
        }
        ENGINE_free(loader);

        /* The loaded engine is now registered; retrieve it by ID */
        engine = ENGINE_by_id(STSAFE_ENGINE_ID);
        if (engine == NULL) {
            printf(PRINT_RED
                   "   ERROR: ENGINE_by_id(\"" STSAFE_ENGINE_ID "\") failed "
                   "after dynamic load\n\r" PRINT_RESET);
            print_openssl_errors();
            goto cleanup;
        }
    }

    /* Configure I2C before ENGINE_init() */
    ENGINE_ctrl_cmd(engine, "I2C_BUS",   STSAFE_I2C_BUS,       NULL, NULL, 0);
    ENGINE_ctrl_cmd(engine, "I2C_SPEED", STSAFE_I2C_SPEED_KHZ, NULL, NULL, 0);
    ENGINE_ctrl_cmd(engine, "CERT_ZONE", STSAFE_CERT_ZONE,      NULL, NULL, 0);
    ENGINE_ctrl_cmd(engine, "KEY_SLOT",  STSAFE_KEY_SLOT,       NULL, NULL, 0);

    /* Initialise the engine (opens I2C bus, calls stse_init inside .so) */
    if (!ENGINE_init(engine)) {
        printf(PRINT_RED "   ERROR: ENGINE_init failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }

    printf("   Engine '%s' loaded: %s\n\r",
           ENGINE_get_id(engine), ENGINE_get_name(engine));

    /* -----------------------------------------------------------------------
     * Step 2 – Load device certificate via LOAD_CERT engine control
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN
           "\n\r## Step 2 – Load device certificate (dynamic engine, zone %d)"
           "\n\r" PRINT_RESET, STSAFE_CERT_ZONE);

    if (!ENGINE_ctrl_cmd(engine, "LOAD_CERT",
                          (long)STSAFE_CERT_ZONE, &dev_cert, NULL, 0)
        || dev_cert == NULL) {
        printf(PRINT_RED
               "   ERROR: ENGINE_ctrl_cmd(LOAD_CERT) failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }
    print_cert_info(dev_cert, "Device certificate");

    /* -----------------------------------------------------------------------
     * Step 3 – Load private key via ENGINE_load_private_key
     *          key_id = "<slot>" or "<slot>:<zone>"
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN
           "\n\r## Step 3 – Load STSAFE-backed private key via engine "
           "(slot %d)\n\r" PRINT_RESET, STSAFE_KEY_SLOT);
    {
        char key_id[32];
        snprintf(key_id, sizeof(key_id), "%d:%d",
                 STSAFE_KEY_SLOT, STSAFE_CERT_ZONE);

        dev_key = ENGINE_load_private_key(engine, key_id, NULL, NULL);
        if (dev_key == NULL) {
            printf(PRINT_RED
                   "   ERROR: ENGINE_load_private_key(\"%s\") failed\n\r"
                   PRINT_RESET, key_id);
            print_openssl_errors();
            goto cleanup;
        }
    }
    printf("   Engine-backed private key loaded (ECDSA/P-256, slot %d)\n\r",
           STSAFE_KEY_SLOT);

#else  /* STSAFE_USE_DYNAMIC_ENGINE not defined → static engine */
    /* =======================================================================
     * STATIC ENGINE MODE  (default)
     * The engine is linked directly into this binary.  The application
     * initialises the stse_Handler_t and passes it to the engine API.
     * ===================================================================== */

    /* -----------------------------------------------------------------------
     * Step 1 – Initialise the STSAFE-A120 device handler
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "## Step 1 – Initialise STSAFE-A120\n\r" PRINT_RESET);

    stse_ret = stse_set_default_handler_value(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "   ERROR: stse_set_default_handler_value (0x%04X)\n\r"
               PRINT_RESET, (unsigned int)stse_ret);
        goto cleanup;
    }

    stse_handler.device_type   = STSAFE_A120;
    stse_handler.io.busID      = STSAFE_I2C_BUS;
    stse_handler.io.BusSpeed   = STSAFE_I2C_SPEED_KHZ;
#ifdef STSE_CONF_USE_STATIC_PERSONALIZATION_INFORMATIONS
    static stse_perso_info_t spl05_perso = {
        .cmd_AC_status     = 0x5555555555545555ULL,
        .ext_cmd_AC_status = 0x5555555555555555ULL,
    };
    stse_handler.perso_info = spl05_perso;
#endif

    stse_ret = stse_init(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "   ERROR: stse_init (0x%04X)\n\r" PRINT_RESET,
               (unsigned int)stse_ret);
        goto cleanup;
    }
    printf("   STSAFE-A120 initialised on /dev/i2c-%d\n\r", STSAFE_I2C_BUS);

    /* -----------------------------------------------------------------------
     * Step 2 – Register the STSAFE OpenSSL engine (static)
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "\n\r## Step 2 – Register STSAFE OpenSSL engine\n\r"
           PRINT_RESET);

    engine = stsafe_engine_get();
    if (engine == NULL) {
        printf(PRINT_RED "   ERROR: stsafe_engine_get failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }
    printf("   Engine '%s' registered: %s\n\r",
           ENGINE_get_id(engine), ENGINE_get_name(engine));

    /* -----------------------------------------------------------------------
     * Step 3 – Load the device certificate from STSAFE zone
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "\n\r## Step 3 – Load device certificate from STSAFE zone %d\n\r"
           PRINT_RESET, STSAFE_CERT_ZONE);

    dev_cert = stsafe_engine_load_cert(&stse_handler, STSAFE_CERT_ZONE);
    if (dev_cert == NULL) {
        printf(PRINT_RED "   ERROR: stsafe_engine_load_cert failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }
    print_cert_info(dev_cert, "Device certificate");

    /* -----------------------------------------------------------------------
     * Step 4 – Create engine-backed private key
     *          Extract the public EC_KEY from the device certificate so the
     *          engine can copy the curve group and public point to the new key.
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "\n\r## Step 4 – Create STSAFE-backed private key (slot %d)\n\r"
           PRINT_RESET, STSAFE_KEY_SLOT);

    {
        EVP_PKEY *cert_pub = X509_get0_pubkey(dev_cert);
        if (cert_pub == NULL || EVP_PKEY_id(cert_pub) != EVP_PKEY_EC) {
            printf(PRINT_RED
                   "   ERROR: certificate does not contain an EC public key\n\r"
                   PRINT_RESET);
            goto cleanup;
        }

        const EC_KEY *pub_ec_key = EVP_PKEY_get0_EC_KEY(cert_pub);
        if (pub_ec_key == NULL) {
            printf(PRINT_RED "   ERROR: EVP_PKEY_get0_EC_KEY failed\n\r"
                   PRINT_RESET);
            goto cleanup;
        }

        dev_key = stsafe_engine_load_key(engine, &stse_handler,
                                          STSAFE_KEY_SLOT,
                                          STSE_ECC_KT_NIST_P_256,
                                          (EC_KEY *)(uintptr_t)pub_ec_key);
        if (dev_key == NULL) {
            printf(PRINT_RED "   ERROR: stsafe_engine_load_key failed\n\r"
                   PRINT_RESET);
            print_openssl_errors();
            goto cleanup;
        }
    }
    printf("   Engine-backed private key created (ECDSA/P-256, slot %d)\n\r",
           STSAFE_KEY_SLOT);

#endif /* STSAFE_USE_DYNAMIC_ENGINE */

    /* -----------------------------------------------------------------------
     * Step 5 – Configure SSL_CTX
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "\n\r## Step 5 – Configure SSL context\n\r" PRINT_RESET);

    /* Use TLS_client_method() for TLS 1.2 and 1.3 */
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL) {
        printf(PRINT_RED "   ERROR: SSL_CTX_new failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }

    /* Require peer certificate verification */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    /* Load CA trust store */
    if (TLS_CA_BUNDLE != NULL) {
        if (SSL_CTX_load_verify_locations(ssl_ctx,
                                          (const char *)TLS_CA_BUNDLE,
                                          NULL) != 1) {
            printf(PRINT_RED "   ERROR: SSL_CTX_load_verify_locations(%s)\n\r"
                   PRINT_RESET, (const char *)TLS_CA_BUNDLE);
            print_openssl_errors();
            goto cleanup;
        }
        printf("   CA bundle loaded from: %s\n\r", (const char *)TLS_CA_BUNDLE);
    } else {
        /* Use the system default CA certificate store */
        if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
            printf(PRINT_RED
                   "   ERROR: SSL_CTX_set_default_verify_paths failed\n\r"
                   PRINT_RESET);
            print_openssl_errors();
            goto cleanup;
        }
        printf("   Using system default CA store\n\r");
    }

    /* Install the device certificate for mutual TLS client authentication */
    if (SSL_CTX_use_certificate(ssl_ctx, dev_cert) != 1) {
        printf(PRINT_RED "   ERROR: SSL_CTX_use_certificate failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }

    /* Install the engine-backed private key */
    if (SSL_CTX_use_PrivateKey(ssl_ctx, dev_key) != 1) {
        printf(PRINT_RED "   ERROR: SSL_CTX_use_PrivateKey failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }

    /* Sanity check: confirm the key matches the certificate */
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        printf(PRINT_RED
               "   ERROR: SSL_CTX_check_private_key – key/cert mismatch\n\r"
               PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }
    printf("   SSL context configured (certificate + engine key installed)\n\r");

    /* -----------------------------------------------------------------------
     * Step 6 – Establish TCP connection + TLS handshake
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "\n\r## Step 6 – Connect to %s:%s\n\r" PRINT_RESET,
           TLS_SERVER_HOST, TLS_SERVER_PORT);

    tcp_fd = tcp_connect(TLS_SERVER_HOST, TLS_SERVER_PORT);
    if (tcp_fd < 0) {
        printf(PRINT_RED "   ERROR: TCP connection to %s:%s failed\n\r" PRINT_RESET,
               TLS_SERVER_HOST, TLS_SERVER_PORT);
        goto cleanup;
    }
    printf("   TCP connection established (fd=%d)\n\r", tcp_fd);

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        printf(PRINT_RED "   ERROR: SSL_new failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }

    /* Enable SNI */
    SSL_set_tlsext_host_name(ssl, TLS_SERVER_HOST);

    /* Bind the SSL object to the socket */
    if (SSL_set_fd(ssl, tcp_fd) != 1) {
        printf(PRINT_RED "   ERROR: SSL_set_fd failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }

    printf("   Performing TLS handshake ...\n\r");
    printf("   (If the server requests a client certificate, ECDSA signing\n\r");
    printf("    will be performed by the STSAFE-A120 via I2C)\n\r");

    if (SSL_connect(ssl) != 1) {
        printf(PRINT_RED "   ERROR: TLS handshake failed\n\r" PRINT_RESET);
        print_openssl_errors();
        goto cleanup;
    }

    /* Print negotiated TLS details */
    printf(PRINT_GREEN "   TLS handshake successful!\n\r" PRINT_RESET);
    printf("   Protocol : %s\n\r", SSL_get_version(ssl));
    printf("   Cipher   : %s\n\r", SSL_get_cipher(ssl));

    /* Print server certificate information */
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert != NULL) {
        print_cert_info(server_cert, "Server certificate");
        X509_free(server_cert);
    }

    /* Verify server certificate chain */
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        printf(PRINT_YELLOW
               "   WARNING: Server cert verification: %s\n\r" PRINT_RESET,
               X509_verify_cert_error_string(verify_result));
    } else {
        printf("   Server certificate verification: " PRINT_GREEN "OK\n\r" PRINT_RESET);
    }

    /* -----------------------------------------------------------------------
     * Step 7 – Send HTTP GET and print response
     * -------------------------------------------------------------------- */
    printf(PRINT_CYAN "\n\r## Step 7 – HTTP GET %s%s\n\r" PRINT_RESET,
           TLS_SERVER_HOST, TLS_SERVER_PATH);

    if (tls_send_http_get(ssl, TLS_SERVER_HOST, TLS_SERVER_PATH) != 0) {
        printf(PRINT_RED "   ERROR: failed to send HTTP GET\n\r" PRINT_RESET);
        goto cleanup;
    }
    tls_print_response(ssl);

    /* -----------------------------------------------------------------------
     * Done
     * -------------------------------------------------------------------- */
    printf(PRINT_GREEN
           "\n\r=========================================================="
           "======================\n\r");
    printf(" TLS Client example completed successfully.\n\r");
    printf(" The STSAFE-A120 signed the TLS CertificateVerify message using\n\r");
    printf(" its private key stored in slot %d – the key never left the device.\n\r",
           STSAFE_KEY_SLOT);
    printf("==========================================================="
           "=====================" PRINT_RESET "\n\r");

    exit_code = 0;

cleanup:
    /* Ordered teardown */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (tcp_fd >= 0) {
        close(tcp_fd);
    }
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
    }
    if (dev_key != NULL) {
        EVP_PKEY_free(dev_key);
    }
    if (dev_cert != NULL) {
        X509_free(dev_cert);
    }
    /* engine is owned by the engine registry; do not ENGINE_free() here */
    EVP_cleanup();
    ERR_free_strings();

    return exit_code;
}

/* ---------------------------------------------------------------------------
 * Helper: establish a TCP connection
 * ---------------------------------------------------------------------- */

/**
 * @brief  Resolve @p host / @p port and return a connected socket fd.
 * @return Socket file descriptor >= 0, or -1 on failure.
 */
static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;    /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        fprintf(stderr, "tcp_connect: getaddrinfo(%s:%s) failed\n", host, port);
        return -1;
    }

    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; /* success */
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* ---------------------------------------------------------------------------
 * Helper: print pending OpenSSL error queue
 * ---------------------------------------------------------------------- */

static void print_openssl_errors(void)
{
    unsigned long err;
    char buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "   [OpenSSL] %s\n", buf);
    }
}

/* ---------------------------------------------------------------------------
 * Helper: print subject/issuer of an X.509 certificate
 * ---------------------------------------------------------------------- */

static void print_cert_info(X509 *cert, const char *label)
{
    if (cert == NULL) return;

    char subject[256] = {0};
    char issuer[256]  = {0};

    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject) - 1);
    X509_NAME_oneline(X509_get_issuer_name(cert),  issuer,  sizeof(issuer)  - 1);

    printf("   %s:\n\r", label);
    printf("     Subject : %s\n\r", subject);
    printf("     Issuer  : %s\n\r", issuer);
}

/* ---------------------------------------------------------------------------
 * Helper: send an HTTP/1.1 GET request over TLS
 * ---------------------------------------------------------------------- */

/**
 * @brief  Write an HTTP/1.1 GET request to @p ssl.
 * @return 0 on success, -1 on write error.
 */
static int tls_send_http_get(SSL *ssl, const char *host, const char *path)
{
    char req[512];
    int  req_len;

    req_len = snprintf(req, sizeof(req),
                       "GET %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       path, host);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        return -1;
    }

    int written = SSL_write(ssl, req, req_len);
    if (written <= 0) {
        print_openssl_errors();
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Helper: read + print the first few lines of the HTTP response
 * ---------------------------------------------------------------------- */

static void tls_print_response(SSL *ssl)
{
    char    buf[TLS_READ_BUF_SIZE + 1];
    int     bytes;
    size_t  total    = 0;
    int     header_done = 0;

    printf("   Server response (headers):\n\r");

    while (!header_done) {
        bytes = SSL_read(ssl, buf, TLS_READ_BUF_SIZE);
        if (bytes <= 0) break;

        buf[bytes] = '\0';
        total += (size_t)bytes;

        /* Print only the HTTP response headers (up to the blank line) */
        char *end_of_headers = strstr(buf, "\r\n\r\n");
        if (end_of_headers != NULL) {
            *end_of_headers = '\0';
            header_done = 1;
        }
        printf("%s\n\r", buf);
    }
    printf("   (total bytes read: %zu)\n\r", total);
}
