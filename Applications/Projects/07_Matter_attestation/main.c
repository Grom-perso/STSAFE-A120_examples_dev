/******************************************************************************
 * \file    main.c
 * \brief   STSAFE-A120 Matter Device Attestation example.
 *
 *          This example demonstrates the complete Matter device attestation
 *          flow using the stse_matter plugin:
 *
 *           1. The STSAFE-A120 is initialised using the portable platform
 *              layer (function-pointer-based I2C and delay).
 *           2. The Device Attestation Certificate (DAC) and Product
 *              Attestation Intermediate (PAI) certificate are retrieved
 *              from the STSAFE data zones using stse_matter_get_dac_chain().
 *           3. A simulated Matter attestation challenge (nonce) is signed
 *              by the STSAFE private key using stse_matter_sign_attestation().
 *           4. The resulting DER-encoded ECDSA signature is displayed.
 *
 *          The example is designed to run on any Linux host (Raspberry Pi,
 *          STM32MP1, ESP-IDF, …) that provides an I2C bus.
 *
 *          Usage (Linux):
 *            ./07_Matter_attestation [i2c_bus] [i2c_addr]
 *
 *          Defaults:
 *            i2c_bus  = /dev/i2c-1
 *            i2c_addr = 0x20
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

#include "Middleware/Matter/stse_matter.h"
#include "Platform_Portable/stse_platform_portable.h"
#include "stselib.h"

#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/* --------------------------------------------------------------------------
 * Linux I2C / delay platform callbacks
 * -------------------------------------------------------------------------- */

static int g_i2c_fd   = -1;
static uint8_t g_i2c_addr = 0x20;

static int plat_i2c_write(uint8_t dev_addr, const uint8_t *p_data,
                           uint16_t length)
{
    if (ioctl(g_i2c_fd, I2C_SLAVE, dev_addr) < 0) return -1;
    if (length == 0) return 0;
    return (write(g_i2c_fd, p_data, length) == length) ? 0 : -1;
}

static int plat_i2c_read(uint8_t dev_addr, uint8_t *p_data, uint16_t length)
{
    if (ioctl(g_i2c_fd, I2C_SLAVE, dev_addr) < 0) return -1;
    return (read(g_i2c_fd, p_data, length) == length) ? 0 : -1;
}

static void plat_delay_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000UL;
    ts.tv_nsec = (ms % 1000UL) * 1000000L;
    nanosleep(&ts, NULL);
}

/* --------------------------------------------------------------------------
 * Utility: print a buffer as hex
 * -------------------------------------------------------------------------- */

static void print_hex(const char *label, const uint8_t *buf, uint16_t len)
{
    printf("  %s (%u bytes):\n    ", label, len);
    for (uint16_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 32 == 0 && (i + 1) < len) {
            printf("\n    ");
        }
    }
    printf("\n");
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *i2c_bus  = (argc > 1) ? argv[1] : "/dev/i2c-1";
    uint8_t     i2c_addr = (argc > 2) ? (uint8_t)strtol(argv[2], NULL, 0)
                                       : 0x20;

    printf("-----------------------------------------------------------\n");
    printf(" STSAFE-A120 Matter Device Attestation Example\n");
    printf("-----------------------------------------------------------\n");
    printf(" I2C bus  : %s\n", i2c_bus);
    printf(" I2C addr : 0x%02X\n", i2c_addr);
    printf("-----------------------------------------------------------\n");

    /* Open the I2C bus */
    g_i2c_fd   = open(i2c_bus, O_RDWR);
    g_i2c_addr = i2c_addr;
    if (g_i2c_fd < 0) {
        perror("[ERROR] open I2C bus");
        return EXIT_FAILURE;
    }

    /* Register platform I/O function pointers */
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

    /* Initialise STSAFE-A120 handler */
    stse_Handler_t     stse;
    stse_ReturnCode_t  ret;

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
    printf("[OK] STSAFE-A120 initialised\n");

    /* ------------------------------------------------------------------ */
    /* Step 1 – Retrieve DAC and PAI certificate chain                     */
    /* ------------------------------------------------------------------ */

    uint8_t  dac[STSE_MATTER_MAX_CERT_SIZE];
    uint16_t dac_len = sizeof(dac);
    uint8_t  pai[STSE_MATTER_MAX_CERT_SIZE];
    uint16_t pai_len = sizeof(pai);

    ret = stse_matter_get_dac_chain(&stse, dac, &dac_len, pai, &pai_len);
    if (ret != STSE_OK) {
        fprintf(stderr, "[ERROR] stse_matter_get_dac_chain: 0x%04X\n", ret);
        close(g_i2c_fd);
        return EXIT_FAILURE;
    }
    printf("[OK] Certificate chain retrieved\n");
    print_hex("DAC (DER)", dac, dac_len);
    print_hex("PAI (DER)", pai, pai_len);

    /* ------------------------------------------------------------------ */
    /* Step 2 – Sign a simulated attestation challenge                     */
    /* ------------------------------------------------------------------ */

    /* In a real Matter flow this is the AttestationElements TBS structure
     * passed by the commissioner.  Here we use a fixed 32-byte nonce. */
    static const uint8_t attestation_challenge[32] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x99,
    };

    uint8_t  signature[STSE_MATTER_MAX_SIG_SIZE];
    uint16_t sig_len = sizeof(signature);

    ret = stse_matter_sign_attestation(&stse,
                                       attestation_challenge,
                                       sizeof(attestation_challenge),
                                       signature,
                                       &sig_len);
    if (ret != STSE_OK) {
        fprintf(stderr, "[ERROR] stse_matter_sign_attestation: 0x%04X\n", ret);
        close(g_i2c_fd);
        return EXIT_FAILURE;
    }
    printf("[OK] Attestation challenge signed\n");
    print_hex("DER signature", signature, sig_len);

    /* ------------------------------------------------------------------ */

    close(g_i2c_fd);

    printf("-----------------------------------------------------------\n");
    printf("[PASS] Matter attestation flow completed successfully\n");
    printf("-----------------------------------------------------------\n");

    return EXIT_SUCCESS;
}
