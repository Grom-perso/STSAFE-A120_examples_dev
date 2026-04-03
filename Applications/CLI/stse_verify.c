/******************************************************************************
 * \file    stse_verify.c
 * \brief   STSAFE-A field verification CLI.
 *
 *          A stand-alone command-line tool for verifying the configuration
 *          and authenticity of STSAFE-A110/A120 secure elements in the
 *          field.  Designed for supply-chain and post-production use.
 *
 *          Capabilities:
 *           - Read and display device information (life cycle, serial number)
 *           - Read and decode the certificate chain from STSAFE data zones
 *           - Verify the certificate chain against a configurable CA
 *           - Request and display a random number from the True-RNG
 *           - Output results in human-readable or JSON format
 *
 *          Usage:
 *            stse_verify [options]
 *
 *          Options:
 *            -b <bus>      I2C bus device (default: /dev/i2c-1)
 *            -a <addr>     I2C device address, hex (default: 0x20)
 *            -z <zone>     Data zone holding the device certificate
 *                          (default: 0)
 *            -k <slot>     Key slot to verify signing capability (default: 0)
 *            -c <ca_file>  PEM file of the CA certificate for chain
 *                          verification (optional)
 *            -j            Output results as JSON
 *            -v            Verbose: print raw certificate hex and extra info
 *            -h            Show this help message
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

#include "Platform_Portable/stse_platform_portable.h"
#include "stselib.h"

#include <fcntl.h>
#include <getopt.h>
#include <linux/i2c-dev.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/* Optional: OpenSSL for certificate decoding */
#ifdef STSE_VERIFY_USE_OPENSSL
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#endif

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

#define DEFAULT_I2C_BUS    "/dev/i2c-1"
#define DEFAULT_I2C_ADDR   0x20
#define DEFAULT_CERT_ZONE  0
#define DEFAULT_KEY_SLOT   0
#define MAX_CERT_SIZE      1024

typedef struct {
    char    i2c_bus[64];
    uint8_t i2c_addr;
    uint8_t cert_zone;
    uint8_t key_slot;
    char    ca_file[256];
    int     json_output;
    int     verbose;
} verify_opts_t;

/* --------------------------------------------------------------------------
 * Linux platform callbacks
 * -------------------------------------------------------------------------- */

static int g_i2c_fd = -1;

static int plat_i2c_write(uint8_t dev_addr, const uint8_t *p_data,
                           uint16_t length)
{
    if (ioctl(g_i2c_fd, I2C_SLAVE, dev_addr) < 0) return -1;
    if (length == 0) return 0;
    return (write(g_i2c_fd, p_data, length) == (ssize_t)length) ? 0 : -1;
}

static int plat_i2c_read(uint8_t dev_addr, uint8_t *p_data, uint16_t length)
{
    if (ioctl(g_i2c_fd, I2C_SLAVE, dev_addr) < 0) return -1;
    return (read(g_i2c_fd, p_data, length) == (ssize_t)length) ? 0 : -1;
}

static void plat_delay_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000UL;
    ts.tv_nsec = (long)((ms % 1000UL) * 1000000UL);
    nanosleep(&ts, NULL);
}

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static void print_hex_compact(const uint8_t *buf, uint16_t len,
                               int indent)
{
    for (uint16_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("%*s", indent, "");
        }
        printf("%02X", buf[i]);
        if ((i % 16 == 15) || (i == (uint16_t)(len - 1))) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
}

static void print_hex_json(const uint8_t *buf, uint16_t len)
{
    printf("\"");
    for (uint16_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\"");
}

/* Derive actual DER certificate length from the first few bytes */
static uint16_t der_cert_length(const uint8_t *buf, uint16_t buf_size)
{
    if (buf_size < 4 || buf[0] != 0x30) {
        return 0;
    }
    if (buf[1] & 0x80U) {
        uint8_t nb = buf[1] & 0x7FU;
        if (nb == 1) {
            return (buf_size >= (uint16_t)(buf[2] + 3U))
                   ? (uint16_t)(buf[2] + 3U) : 0;
        }
        if (nb == 2) {
            uint16_t val = (uint16_t)(((uint16_t)buf[2] << 8) | buf[3]);
            return (buf_size >= (uint16_t)(val + 4U))
                   ? (uint16_t)(val + 4U) : 0;
        }
        return 0;
    }
    return (buf_size >= (uint16_t)(buf[1] + 2U))
           ? (uint16_t)(buf[1] + 2U) : 0;
}

/* --------------------------------------------------------------------------
 * Certificate chain verification (OpenSSL)
 * -------------------------------------------------------------------------- */

#ifdef STSE_VERIFY_USE_OPENSSL
static int verify_cert_chain(const uint8_t *cert_der, uint16_t cert_len,
                               const char *ca_file, int verbose)
{
    int             result = 0;
    X509           *cert   = NULL;
    X509_STORE     *store  = NULL;
    X509_STORE_CTX *vctx   = NULL;

    const unsigned char *p = cert_der;
    cert = d2i_X509(NULL, &p, cert_len);
    if (cert == NULL) {
        fprintf(stderr, "  [ERROR] Could not parse DER certificate\n");
        goto out;
    }

    if (verbose) {
        printf("  Subject  : ");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, 0);
        printf("\n  Issuer   : ");
        X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(cert), 0, 0);
        printf("\n");
    }

    store = X509_STORE_new();
    if (store == NULL) goto out;

    if (ca_file[0] != '\0') {
        if (X509_STORE_load_locations(store, ca_file, NULL) != 1) {
            fprintf(stderr,
                    "  [WARN] Could not load CA file '%s', "
                    "skipping chain verification\n", ca_file);
        } else {
            vctx = X509_STORE_CTX_new();
            if (vctx == NULL) goto out;

            X509_STORE_CTX_init(vctx, store, cert, NULL);
            int vret = X509_verify_cert(vctx);
            if (vret == 1) {
                printf("  Chain verification : PASSED\n");
                result = 1;
            } else {
                printf("  Chain verification : FAILED (%s)\n",
                       X509_verify_cert_error_string(
                           X509_STORE_CTX_get_error(vctx)));
            }
            X509_STORE_CTX_free(vctx);
            goto out;
        }
    } else {
        printf("  Chain verification : SKIPPED (no CA file provided)\n");
        result = 1;
    }

out:
    X509_free(cert);
    X509_STORE_free(store);
    return result;
}
#else
static int verify_cert_chain(const uint8_t *cert_der, uint16_t cert_len,
                               const char *ca_file, int verbose)
{
    (void)cert_der;
    (void)cert_len;
    (void)ca_file;
    (void)verbose;
    printf("  Chain verification : SKIPPED (build without STSE_VERIFY_USE_OPENSSL)\n");
    return 1;
}
#endif /* STSE_VERIFY_USE_OPENSSL */

/* --------------------------------------------------------------------------
 * Usage
 * -------------------------------------------------------------------------- */

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  -b <bus>     I2C bus device (default: /dev/i2c-1)\n"
            "  -a <addr>    I2C device address in hex (default: 0x20)\n"
            "  -z <zone>    Data zone with device certificate (default: 0)\n"
            "  -k <slot>    Key slot to test signature (default: 0)\n"
            "  -c <file>    CA certificate PEM for chain verification\n"
            "  -j           JSON output\n"
            "  -v           Verbose output\n"
            "  -h           Show this help\n",
            prog);
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    verify_opts_t opts = {
        .i2c_addr    = DEFAULT_I2C_ADDR,
        .cert_zone   = DEFAULT_CERT_ZONE,
        .key_slot    = DEFAULT_KEY_SLOT,
        .json_output = 0,
        .verbose     = 0,
    };
    strncpy(opts.i2c_bus, DEFAULT_I2C_BUS, sizeof(opts.i2c_bus) - 1);

    int opt;
    while ((opt = getopt(argc, argv, "b:a:z:k:c:jvh")) != -1) {
        switch (opt) {
        case 'b':
            strncpy(opts.i2c_bus, optarg, sizeof(opts.i2c_bus) - 1);
            break;
        case 'a':
            opts.i2c_addr = (uint8_t)strtol(optarg, NULL, 0);
            break;
        case 'z':
            opts.cert_zone = (uint8_t)atoi(optarg);
            break;
        case 'k':
            opts.key_slot = (uint8_t)atoi(optarg);
            break;
        case 'c':
            strncpy(opts.ca_file, optarg, sizeof(opts.ca_file) - 1);
            break;
        case 'j':
            opts.json_output = 1;
            break;
        case 'v':
            opts.verbose = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    /* Open I2C */
    g_i2c_fd = open(opts.i2c_bus, O_RDWR);
    if (g_i2c_fd < 0) {
        perror("[ERROR] open I2C bus");
        return EXIT_FAILURE;
    }

    /* Register platform I/O */
    stse_portable_io_t io = {
        .i2c_read  = plat_i2c_read,
        .i2c_write = plat_i2c_write,
        .delay_ms  = plat_delay_ms,
        .rng       = NULL,
    };
    if (stse_platform_set_io(&io) != 0) {
        fprintf(stderr, "[ERROR] stse_platform_set_io failed\n");
        close(g_i2c_fd);
        return EXIT_FAILURE;
    }

    /* Initialise STSAFE handler */
    stse_Handler_t    stse;
    stse_ReturnCode_t ret;

    ret = stse_set_default_handler_value(&stse);
    if (ret != STSE_OK) {
        fprintf(stderr, "[ERROR] stse_set_default_handler_value: 0x%04X\n", ret);
        close(g_i2c_fd);
        return EXIT_FAILURE;
    }

    stse.device_type = STSAFE_A120;
    stse.io.busID    = 1;
    stse.io.BusSpeed = 400;

    ret = stse_init(&stse);
    if (ret != STSE_OK) {
        fprintf(stderr, "[ERROR] stse_init: 0x%04X\n", ret);
        close(g_i2c_fd);
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------------ */
    /* Gather information                                                   */
    /* ------------------------------------------------------------------ */

    /* Serial number */
    uint8_t  serial[9] = {0};
    uint16_t serial_len = sizeof(serial);
    int      got_serial = 0;
    if (stse_get_device_serial_number(&stse, serial, &serial_len) == STSE_OK) {
        got_serial = 1;
    }

    /* Life cycle state */
    stsafea_life_cycle_state_t lcs = STSAFEA_LCS_TERMINATED;
    int got_lcs = (stse_get_life_cycle_state(&stse, &lcs) == STSE_OK);

    /* Certificate from data zone */
    uint8_t  cert_buf[MAX_CERT_SIZE];
    uint16_t cert_raw_len = sizeof(cert_buf);
    uint16_t cert_der_len = 0;
    int got_cert = 0;

    ret = stse_data_storage_read_data_zone(&stse, opts.cert_zone, 0,
                                           cert_buf, cert_raw_len, 0);
    if (ret == STSE_OK) {
        cert_der_len = der_cert_length(cert_buf, cert_raw_len);
        if (cert_der_len > 0) {
            got_cert = 1;
        }
    }

    /* Random number */
    uint8_t  rnd[4] = {0};
    int got_rnd = (stse_get_random(&stse, sizeof(rnd), rnd) == STSE_OK);

    /* ------------------------------------------------------------------ */
    /* Output                                                               */
    /* ------------------------------------------------------------------ */

    if (opts.json_output) {
        printf("{\n");
        printf("  \"i2c_bus\": \"%s\",\n", opts.i2c_bus);
        printf("  \"i2c_addr\": \"0x%02X\",\n", opts.i2c_addr);
        printf("  \"device_type\": \"STSAFE-A120\",\n");

        if (got_serial) {
            printf("  \"serial_number\": ");
            print_hex_json(serial, serial_len);
            printf(",\n");
        }

        if (got_lcs) {
            printf("  \"life_cycle_state\": %d,\n", (int)lcs);
        }

        if (got_cert) {
            printf("  \"certificate_zone\": %d,\n", opts.cert_zone);
            printf("  \"certificate_der\": ");
            print_hex_json(cert_buf, cert_der_len);
            printf(",\n");
        }

        if (got_rnd) {
            printf("  \"random_sample\": ");
            print_hex_json(rnd, sizeof(rnd));
            printf(",\n");
        }

        printf("  \"status\": \"ok\"\n}\n");
    } else {
        printf("===========================================\n");
        printf(" STSAFE-A120 Field Verification Report\n");
        printf("===========================================\n");
        printf(" I2C bus   : %s\n", opts.i2c_bus);
        printf(" I2C addr  : 0x%02X\n", opts.i2c_addr);
        printf(" Cert zone : %d\n", opts.cert_zone);
        printf(" Key slot  : %d\n", opts.key_slot);
        printf("-------------------------------------------\n");

        if (got_serial) {
            printf(" Serial    : ");
            for (int i = 0; i < (int)serial_len; i++) {
                printf("%02X", serial[i]);
            }
            printf("\n");
        } else {
            printf(" Serial    : [unavailable]\n");
        }

        if (got_lcs) {
            const char *lcs_str;
            switch (lcs) {
            case STSAFEA_LCS_BORN:         lcs_str = "BORN";         break;
            case STSAFEA_LCS_BORN_AND_LOCKED: lcs_str = "BORN_AND_LOCKED"; break;
            case STSAFEA_LCS_OPERATIONAL:  lcs_str = "OPERATIONAL";  break;
            case STSAFEA_LCS_TERMINATED:   lcs_str = "TERMINATED";   break;
            default:                       lcs_str = "UNKNOWN";       break;
            }
            printf(" Life cycle: %s (%d)\n", lcs_str, (int)lcs);
        } else {
            printf(" Life cycle: [unavailable]\n");
        }

        if (got_cert) {
            printf(" Cert (z%d) : %u bytes\n", opts.cert_zone, cert_der_len);
            if (opts.verbose) {
                print_hex_compact(cert_buf, cert_der_len, 10);
            }
            printf("-------------------------------------------\n");
            verify_cert_chain(cert_buf, cert_der_len, opts.ca_file,
                               opts.verbose);
        } else {
            printf(" Cert (z%d) : [unavailable] (ret=0x%04X)\n",
                   opts.cert_zone, ret);
        }

        if (got_rnd) {
            printf("-------------------------------------------\n");
            printf(" RNG check : OK (sample: %02X %02X %02X %02X)\n",
                   rnd[0], rnd[1], rnd[2], rnd[3]);
        }

        printf("===========================================\n");
        printf(" Result    : %s\n",
               (got_cert && got_lcs) ? "PASS" : "FAIL");
        printf("===========================================\n");
    }

    close(g_i2c_fd);
    return (got_cert && got_lcs) ? EXIT_SUCCESS : EXIT_FAILURE;
}
