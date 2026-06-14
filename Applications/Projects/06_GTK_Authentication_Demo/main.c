/**
 ******************************************************************************
 * @file    main.c
 * @author  CS application team
 * @brief   STSAFE-A120 Graphical Authentication Demo (GTK3, Linux/MPU)
 ******************************************************************************
 *                      COPYRIGHT 2022 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 * @details
 *   This example provides a GTK3 graphical interface for STSAFE-A120
 *   device authentication and NVM data inspection on STM32MP1 running
 *   OpenSTLinux.
 *
 *   Features:
 *    - One-click device authentication using the ST production CA certificate
 *    - Certificate chain verification (CA → device certificate in zone 0)
 *    - Challenge-response proof-of-possession using static private key slot 0
 *    - Live display of all User NVM zone partition information (SPL05 layout)
 *    - Hex dump of User NVM zone 1 and zone 2 data
 *
 *   STSAFE-A120 SPL05 User NVM zone layout (reference):
 *    Zone 0 : Device certificate  (~500 B, Read: ALWAYS, Write: NEVER)
 *    Zone 1 : User NVM data 1     (100 B,  Read: ALWAYS, Write: ALWAYS)
 *    Zone 2 : User NVM data 2     (100 B,  Read: ALWAYS, Write: ALWAYS)
 *
 *   Build (from repository root, after sourcing the OpenSTLinux SDK):
 *    make EXAMPLE=06_GTK_Authentication_Demo
 *
 *   Requirements:
 *    - GTK+ 3.x development headers  (gtk+-3.0 pkg-config package)
 *    - OpenSSL development headers    (libssl-dev)
 *    - STSELib submodule initialised  (git submodule update --init)
 ******************************************************************************
 */

/* -------------------------------------------------------------------------- */
/* Includes                                                                    */
/* -------------------------------------------------------------------------- */

#include "Apps_utils.h"

#include <gtk/gtk.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* STSAFE-A120 SPL05 constants                                                 */
/* -------------------------------------------------------------------------- */

/**
 * ST STSAFE-A Production CA 01 — self-signed root certificate.
 * Used to verify the device certificate stored in zone 0 for
 * SPL02 / SPL03 / SPL05 personalizations.
 */
#define CA_SELF_SIGNED_CERTIFICATE_01                                             \
    0x30, 0x82, 0x01, 0xA0, 0x30, 0x82, 0x01, 0x46, 0xA0, 0x03, 0x02, 0x01,     \
        0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, \
        0x3D, 0x04, 0x03, 0x02, 0x30, 0x4F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, \
        0x55, 0x04, 0x06, 0x13, 0x02, 0x4E, 0x4C, 0x31, 0x1E, 0x30, 0x1C, 0x06, \
        0x03, 0x55, 0x04, 0x0A, 0x0C, 0x15, 0x53, 0x54, 0x4D, 0x69, 0x63, 0x72, \
        0x6F, 0x65, 0x6C, 0x65, 0x63, 0x74, 0x72, 0x6F, 0x6E, 0x69, 0x63, 0x73, \
        0x20, 0x6E, 0x76, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, \
        0x0C, 0x17, 0x53, 0x54, 0x4D, 0x20, 0x53, 0x54, 0x53, 0x41, 0x46, 0x45, \
        0x2D, 0x41, 0x20, 0x50, 0x52, 0x4F, 0x44, 0x20, 0x43, 0x41, 0x20, 0x30, \
        0x31, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x38, 0x30, 0x37, 0x32, 0x37, 0x30, \
        0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x34, 0x38, 0x30, 0x37, \
        0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x4F, 0x31, \
        0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4E, 0x4C, \
        0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x15, 0x53, \
        0x54, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x65, 0x6C, 0x65, 0x63, 0x74, 0x72, \
        0x6F, 0x6E, 0x69, 0x63, 0x73, 0x20, 0x6E, 0x76, 0x31, 0x20, 0x30, 0x1E, \
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x17, 0x53, 0x54, 0x4D, 0x20, 0x53, \
        0x54, 0x53, 0x41, 0x46, 0x45, 0x2D, 0x41, 0x20, 0x50, 0x52, 0x4F, 0x44, \
        0x20, 0x43, 0x41, 0x20, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, \
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, \
        0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x82, 0x19, 0x4F, \
        0x26, 0xCC, 0xA3, 0x6E, 0x0E, 0x82, 0x19, 0x5C, 0xE6, 0x66, 0x58, 0xEC, \
        0x64, 0xA4, 0x66, 0x92, 0x2F, 0x58, 0xC9, 0xE6, 0x4B, 0x5D, 0xE1, 0xA2, \
        0x9E, 0x7F, 0x39, 0x86, 0x3D, 0x04, 0x26, 0x92, 0xE4, 0xC8, 0xAC, 0x79, \
        0xF9, 0x6D, 0x2F, 0xED, 0x52, 0x77, 0x4D, 0x52, 0x81, 0x95, 0x39, 0xF2, \
        0x1F, 0x3E, 0xCD, 0x19, 0x38, 0xF8, 0x3D, 0x70, 0xAE, 0xE0, 0x9C, 0xCD, \
        0x8D, 0xA3, 0x13, 0x30, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, \
        0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, \
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, \
        0x00, 0x30, 0x45, 0x02, 0x20, 0x6E, 0xE5, 0x43, 0x32, 0x47, 0xAC, 0x72, \
        0x34, 0xFC, 0x9D, 0x17, 0x5A, 0xA5, 0x1E, 0x83, 0x27, 0x69, 0x01, 0xAD, \
        0xEC, 0x1F, 0x00, 0x5E, 0x37, 0x1F, 0x40, 0x73, 0x4D, 0xE3, 0x8C, 0xC5, \
        0x2E, 0x02, 0x21, 0x00, 0xB1, 0xD9, 0x51, 0x6A, 0xAD, 0x9A, 0x3E, 0x86, \
        0xD2, 0x2B, 0x8E, 0x3B, 0x3B, 0xD0, 0x14, 0x6F, 0xAB, 0xB9, 0xB9, 0x22, \
        0xF0, 0x45, 0x26, 0x34, 0xFE, 0x92, 0x7F, 0xF5, 0xD6, 0x36, 0xCD, 0x90

/** Zone index of the device certificate (SPL05 layout) */
#define STSAFE_CERTIFICATE_ZONE_0    0U
/** Static private key slot used for challenge-response authentication */
#define STSE_STATIC_PRIVATE_KEY_SLOT_0 0U
/** I2C bus ID default (maps to /dev/i2c-1 on many STM32MP1 boards) */
#define DEFAULT_I2C_BUS_ID           1U
/** Maximum bytes read per zone for the hex display */
#define ZONE_READ_MAX_BYTES          256U

/* -------------------------------------------------------------------------- */
/* Internal result buffer                                                      */
/* -------------------------------------------------------------------------- */

/** Scratch buffer size for the formatted results pane */
#define RESULT_BUF_SIZE (1024U * 16U)

/* -------------------------------------------------------------------------- */
/* Application state                                                           */
/* -------------------------------------------------------------------------- */

/**
 * @brief  Shared state structure — allocated once, passed by pointer.
 * @note   All GTK widget pointers are accessed on the main thread only.
 *         The STSAFE handler is used exclusively in the worker thread
 *         and must not be touched from the main thread while the worker runs.
 */
typedef struct {
    /* --- GTK widgets (main thread only) --- */
    GtkWidget    *window;
    GtkWidget    *btn_authenticate;
    GtkWidget    *lbl_status;
    GtkWidget    *txt_results;
    GtkWidget    *spin_bus;
    GtkWidget    *spinner;

    /* --- STSAFE handler (worker thread only while running) --- */
    stse_Handler_t stse_handler;

    /* --- Configuration (written before worker starts, read-only after) --- */
    int           bus_id;

    /* --- Result data (written by worker, read on main thread via idle) --- */
    GMutex        result_mutex;
    gboolean      auth_success;
    char          result_text[RESULT_BUF_SIZE];
} AppState;

/* -------------------------------------------------------------------------- */
/* Forward declarations                                                        */
/* -------------------------------------------------------------------------- */

static void     on_authenticate_clicked(GtkButton *btn, gpointer user_data);
static gpointer auth_worker_thread(gpointer user_data);
static gboolean update_ui_idle(gpointer user_data);

/* -------------------------------------------------------------------------- */
/* Helper: append formatted text to result buffer                              */
/* -------------------------------------------------------------------------- */

/**
 * @brief  Append a printf-style formatted string to the result buffer.
 * @param  buf      Pointer to the result buffer.
 * @param  buf_size Total size of the result buffer.
 * @param  fmt      printf format string.
 */
static void rbuf_append(char *buf, size_t buf_size, const char *fmt, ...) {
    size_t used = strlen(buf);
    if (used >= buf_size - 1U) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf + used, buf_size - used, fmt, args);
    va_end(args);
}

/* -------------------------------------------------------------------------- */
/* Helper: format a byte buffer as annotated hex dump                          */
/* -------------------------------------------------------------------------- */

/**
 * @brief  Append a hex dump of a byte buffer to the result buffer.
 * @param  buf        Result buffer to append to.
 * @param  buf_size   Size of the result buffer.
 * @param  data       Byte array to format.
 * @param  data_len   Number of bytes in @p data.
 */
static void rbuf_append_hexdump(char       *buf,
                                size_t      buf_size,
                                const uint8_t *data,
                                uint16_t    data_len) {
    for (uint16_t i = 0U; i < data_len; i++) {
        if (i % 16U == 0U) {
            rbuf_append(buf, buf_size, "\n    %04X: ", (unsigned int)i);
        } else if (i % 8U == 0U) {
            rbuf_append(buf, buf_size, " ");
        }
        rbuf_append(buf, buf_size, "%02X ", (unsigned int)data[i]);
    }
    rbuf_append(buf, buf_size, "\n");
}

/* -------------------------------------------------------------------------- */
/* Helper: access condition → human-readable string                            */
/* -------------------------------------------------------------------------- */
static const char *ac_to_str(uint8_t ac) {
    switch (ac) {
    case STSE_AC_ALWAYS: return "ALWAYS";
    case STSE_AC_HOST:   return "HOST";
    case STSE_AC_AUTH:   return "AUTH";
    default:             return "NEVER";
    }
}

/* -------------------------------------------------------------------------- */
/* Worker thread — all STSAFE I/O happens here                                 */
/* -------------------------------------------------------------------------- */

/**
 * @brief  Background thread that performs all STSAFE-A120 operations.
 *
 * Execution sequence:
 *  1. Initialise the STSAFE-A120 handler and open the I2C bus.
 *  2. Authenticate the device (certificate chain + challenge-response).
 *  3. Query and display the User NVM zone partition table.
 *  4. Read and display zone 1 and zone 2 data (SPL05 user zones).
 *  5. Schedule a main-thread idle callback to refresh the GTK UI.
 *
 * @param  user_data  Pointer to the AppState structure.
 * @return NULL
 */
static gpointer auth_worker_thread(gpointer user_data) {
    AppState          *app = (AppState *)user_data;
    stse_ReturnCode_t  ret;
    char              *rbuf    = app->result_text;
    const size_t       rbuf_sz = RESULT_BUF_SIZE;

    static const uint8_t ca_cert[] = {CA_SELF_SIGNED_CERTIFICATE_01};

    /* ------------------------------------------------------------------ */
    /* Reset result buffer                                                 */
    /* ------------------------------------------------------------------ */
    memset(rbuf, 0, rbuf_sz);

    rbuf_append(rbuf, rbuf_sz,
                "══════════════════════════════════════════════════════\n"
                "  STSAFE-A120  Authentication & Data Read\n"
                "  I2C bus: /dev/i2c-%d\n"
                "══════════════════════════════════════════════════════\n\n",
                app->bus_id);

    /* ------------------------------------------------------------------ */
    /* Step 1 — Initialise STSAFE-A120 handler                            */
    /* ------------------------------------------------------------------ */
    rbuf_append(rbuf, rbuf_sz, "[ 1/4 ] Initialising STSAFE-A120 handler...\n");

    ret = stse_set_default_handler_value(&app->stse_handler);
    if (ret != STSE_OK) {
        rbuf_append(rbuf, rbuf_sz,
                    "  ERROR: stse_set_default_handler_value (0x%04X)\n", ret);
        goto done;
    }

    app->stse_handler.device_type  = STSAFE_A120;
    app->stse_handler.io.busID     = (PLAT_UI8)app->bus_id;
    app->stse_handler.io.BusSpeed  = 400U;

    ret = stse_init(&app->stse_handler);
    if (ret != STSE_OK) {
        rbuf_append(rbuf, rbuf_sz,
                    "  ERROR: stse_init (0x%04X)\n"
                    "  Check that /dev/i2c-%d is accessible and that the\n"
                    "  STSAFE-A120 responds at address 0x20.\n",
                    ret, app->bus_id);
        goto done;
    }
    rbuf_append(rbuf, rbuf_sz, "  OK — device found on /dev/i2c-%d\n\n", app->bus_id);

    /* ------------------------------------------------------------------ */
    /* Step 2 — Authenticate the device                                   */
    /* ------------------------------------------------------------------ */
    rbuf_append(rbuf, rbuf_sz,
                "[ 2/4 ] Authenticating device (ST CA cert → zone 0 → key slot 0)...\n");

    ret = stse_device_authenticate(
        &app->stse_handler,
        ca_cert,
        STSAFE_CERTIFICATE_ZONE_0,
        STSE_STATIC_PRIVATE_KEY_SLOT_0);

    if (ret != STSE_OK) {
        app->auth_success = FALSE;
        rbuf_append(rbuf, rbuf_sz,
                    "  ✗  AUTHENTICATION FAILED  (error 0x%04X)\n\n", ret);
    } else {
        app->auth_success = TRUE;
        rbuf_append(rbuf, rbuf_sz, "  ✓  AUTHENTICATION SUCCESSFUL\n\n");
    }

    /* ------------------------------------------------------------------ */
    /* Step 3 — Display User NVM zone partition table                      */
    /* ------------------------------------------------------------------ */
    rbuf_append(rbuf, rbuf_sz, "[ 3/4 ] Reading User NVM partition table...\n");

    uint8_t total_zones = 0U;
    ret = stse_data_storage_get_total_partition_count(&app->stse_handler, &total_zones);
    if (ret != STSE_OK) {
        rbuf_append(rbuf, rbuf_sz,
                    "  ERROR: stse_data_storage_get_total_partition_count (0x%04X)\n\n", ret);
        goto done;
    }

    rbuf_append(rbuf, rbuf_sz, "  Total zones: %u\n\n", (unsigned int)total_zones);
    rbuf_append(rbuf, rbuf_sz,
                "  %-4s | %-7s | %-18s | %-9s | %-9s | %-10s | %-10s\n",
                "Zone", "Counter", "Data Size (bytes)", "Read AC", "Read CR",
                "Update AC", "Update CR");
    rbuf_append(rbuf, rbuf_sz,
                "  ─────┼─────────┼────────────────────┼───────────┼───────────┼────────────┼────────────\n");

    stsafea_data_partition_record_t zones[total_zones];
    uint16_t table_len = (uint16_t)sizeof(zones);

    ret = stse_data_storage_get_partitioning_table(
        &app->stse_handler,
        total_zones,
        zones,
        table_len);
    if (ret != STSE_OK) {
        rbuf_append(rbuf, rbuf_sz,
                    "  ERROR: stse_data_storage_get_partitioning_table (0x%04X)\n\n", ret);
        goto done;
    }

    for (uint8_t i = 0U; i < total_zones; i++) {
        rbuf_append(rbuf, rbuf_sz,
                    "  %-4u | %-7s | %-18u | %-9s | %-9s | %-10s | %-10s\n",
                    (unsigned int)zones[i].index,
                    (zones[i].zone_type != 0U) ? "yes" : "no",
                    (unsigned int)zones[i].data_segment_length,
                    ac_to_str(zones[i].read_ac),
                    zones[i].read_ac_cr ? "allowed" : "denied",
                    ac_to_str(zones[i].update_ac),
                    zones[i].update_ac_cr ? "allowed" : "denied");
    }
    rbuf_append(rbuf, rbuf_sz, "\n");

    /* ------------------------------------------------------------------ */
    /* Step 4 — Read User NVM zone data (zones 1 and 2 in SPL05 layout)   */
    /* ------------------------------------------------------------------ */
    rbuf_append(rbuf, rbuf_sz,
                "[ 4/4 ] Reading User NVM zone data (SPL05: zones 1 & 2)...\n");

    /* Read zones that carry user data (all zones except the certificate zone 0) */
    for (uint8_t i = 0U; i < total_zones; i++) {
        /* Skip the certificate zone and counter-only zones */
        if (zones[i].index == STSAFE_CERTIFICATE_ZONE_0) {
            continue;
        }
        if (zones[i].read_ac == STSE_AC_NEVER) {
            rbuf_append(rbuf, rbuf_sz,
                        "  Zone %u: read access NEVER — skipped\n", zones[i].index);
            continue;
        }

        uint16_t read_len = zones[i].data_segment_length;
        if (read_len == 0U) {
            rbuf_append(rbuf, rbuf_sz, "  Zone %u: data segment empty — skipped\n", zones[i].index);
            continue;
        }
        if (read_len > ZONE_READ_MAX_BYTES) {
            read_len = ZONE_READ_MAX_BYTES;
        }

        uint8_t zone_data[ZONE_READ_MAX_BYTES];

        ret = stse_data_storage_read_data_zone(
            &app->stse_handler,
            zones[i].index, /* Zone index         */
            0x0000U,        /* Read offset        */
            zone_data,      /* Output buffer      */
            read_len,       /* Bytes to read      */
            4U,             /* Read chunk size    */
            STSE_NO_PROT);

        if (ret != STSE_OK) {
            rbuf_append(rbuf, rbuf_sz,
                        "\n  Zone %u  (%u bytes)  — READ ERROR 0x%04X\n",
                        zones[i].index, read_len, ret);
        } else {
            rbuf_append(rbuf, rbuf_sz,
                        "\n  Zone %u  (%u bytes, Read: %s):",
                        zones[i].index, read_len, ac_to_str(zones[i].read_ac));
            rbuf_append_hexdump(rbuf, rbuf_sz, zone_data, read_len);
        }
    }

done:
    rbuf_append(rbuf, rbuf_sz,
                "\n══════════════════════════════════════════════════════\n");

    /* Schedule UI refresh on the GTK main thread */
    g_idle_add(update_ui_idle, app);

    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Idle callback — runs on the GTK main thread after the worker finishes       */
/* -------------------------------------------------------------------------- */

/**
 * @brief  GTK main-thread callback that refreshes all widgets with the results
 *         produced by the worker thread.
 * @param  user_data  Pointer to AppState.
 * @return G_SOURCE_REMOVE (run only once).
 */
static gboolean update_ui_idle(gpointer user_data) {
    AppState *app = (AppState *)user_data;

    /* Update status label */
    if (app->auth_success) {
        gtk_label_set_markup(
            GTK_LABEL(app->lbl_status),
            "<span foreground='#00AA00' weight='bold' size='large'>"
            "✓  AUTHENTICATED"
            "</span>");
    } else {
        gtk_label_set_markup(
            GTK_LABEL(app->lbl_status),
            "<span foreground='#CC0000' weight='bold' size='large'>"
            "✗  AUTHENTICATION FAILED"
            "</span>");
    }

    /* Fill text view with results */
    GtkTextBuffer *tbuf =
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->txt_results));
    gtk_text_buffer_set_text(tbuf, app->result_text, -1);

    /* Scroll text view to the beginning */
    GtkTextIter start;
    gtk_text_buffer_get_start_iter(tbuf, &start);
    gtk_text_view_scroll_to_iter(
        GTK_TEXT_VIEW(app->txt_results), &start,
        0.0, FALSE, 0.0, 0.0);

    /* Re-enable the button and stop the spinner */
    gtk_widget_set_sensitive(app->btn_authenticate, TRUE);
    gtk_spinner_stop(GTK_SPINNER(app->spinner));
    gtk_widget_hide(app->spinner);

    return G_SOURCE_REMOVE;
}

/* -------------------------------------------------------------------------- */
/* Button click handler                                                        */
/* -------------------------------------------------------------------------- */

/**
 * @brief  Called when the user clicks the "Authenticate & Read" button.
 *
 *  - Reads the selected I2C bus number.
 *  - Disables the button and shows the spinner.
 *  - Resets the status label to "Working…".
 *  - Launches the worker thread.
 *
 * @param  btn        The clicked button widget (unused).
 * @param  user_data  Pointer to AppState.
 */
static void on_authenticate_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    AppState *app = (AppState *)user_data;

    /* Read I2C bus ID from spin button */
    app->bus_id = (int)gtk_spin_button_get_value(GTK_SPIN_BUTTON(app->spin_bus));

    /* Disable button and show activity spinner */
    gtk_widget_set_sensitive(app->btn_authenticate, FALSE);
    gtk_widget_show(app->spinner);
    gtk_spinner_start(GTK_SPINNER(app->spinner));

    /* Reset status label */
    gtk_label_set_markup(
        GTK_LABEL(app->lbl_status),
        "<span foreground='#555555' size='large'>⏳  Working…</span>");

    /* Clear results pane */
    GtkTextBuffer *tbuf =
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->txt_results));
    gtk_text_buffer_set_text(tbuf, "", -1);

    /* Start worker thread (detached — GTK idle callback will clean up) */
    GThread *worker = g_thread_new("stsafe-auth", auth_worker_thread, app);
    g_thread_unref(worker);
}

/* -------------------------------------------------------------------------- */
/* UI construction                                                             */
/* -------------------------------------------------------------------------- */

/**
 * @brief  Build and populate the GTK3 application window.
 * @param  app  Pointer to the AppState structure (widgets stored here).
 */
static void build_ui(AppState *app) {
    /* ---- Main window ---- */
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "STSAFE-A120 Authentication Demo");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 760, 620);
    gtk_container_set_border_width(GTK_CONTAINER(app->window), 12);
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* ---- Top-level vertical box ---- */
    GtkWidget *vbox_main = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(app->window), vbox_main);

    /* ---- Banner label ---- */
    GtkWidget *lbl_title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lbl_title),
                         "<b><big>STSAFE-A120 Authentication Demo</big></b>\n"
                         "<small>OpenSTLinux / STM32MP1 — GTK3 example</small>");
    gtk_label_set_justify(GTK_LABEL(lbl_title), GTK_JUSTIFY_CENTER);
    gtk_box_pack_start(GTK_BOX(vbox_main), lbl_title, FALSE, FALSE, 4);

    /* ---- Separator ---- */
    gtk_box_pack_start(GTK_BOX(vbox_main),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
                       FALSE, FALSE, 0);

    /* ---- Control row (bus selector + button + spinner) ---- */
    GtkWidget *hbox_ctrl = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(vbox_main), hbox_ctrl, FALSE, FALSE, 4);

    GtkWidget *lbl_bus = gtk_label_new("I2C bus ID:");
    gtk_box_pack_start(GTK_BOX(hbox_ctrl), lbl_bus, FALSE, FALSE, 0);

    /* SpinButton: integer range 0–15, default DEFAULT_I2C_BUS_ID */
    GtkAdjustment *adj = gtk_adjustment_new(
        (gdouble)DEFAULT_I2C_BUS_ID,   /* value   */
        0.0,                            /* lower   */
        15.0,                           /* upper   */
        1.0,                            /* step    */
        1.0,                            /* page    */
        0.0);                           /* page sz */
    app->spin_bus = gtk_spin_button_new(adj, 1.0, 0);
    gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(app->spin_bus), TRUE);
    gtk_widget_set_tooltip_text(app->spin_bus,
                                "Linux I2C bus number (maps to /dev/i2c-N).\n"
                                "Run 'i2cdetect -l' to list available buses.");
    gtk_box_pack_start(GTK_BOX(hbox_ctrl), app->spin_bus, FALSE, FALSE, 0);

    /* Authenticate button */
    app->btn_authenticate = gtk_button_new_with_label("  Authenticate & Read Device Info  ");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app->btn_authenticate),
        "suggested-action");
    gtk_box_pack_start(GTK_BOX(hbox_ctrl), app->btn_authenticate, FALSE, FALSE, 8);
    g_signal_connect(app->btn_authenticate, "clicked",
                     G_CALLBACK(on_authenticate_clicked), app);

    /* Activity spinner (hidden until button is clicked) */
    app->spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(hbox_ctrl), app->spinner, FALSE, FALSE, 0);
    gtk_widget_hide(app->spinner);

    /* ---- Status label ---- */
    app->lbl_status = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(app->lbl_status),
                         "<span foreground='#555555' size='large'>"
                         "⬤  Idle — press the button to start"
                         "</span>");
    gtk_label_set_xalign(GTK_LABEL(app->lbl_status), 0.0f);
    gtk_widget_set_margin_start(app->lbl_status, 4);
    gtk_box_pack_start(GTK_BOX(vbox_main), app->lbl_status, FALSE, FALSE, 0);

    /* ---- Separator ---- */
    gtk_box_pack_start(GTK_BOX(vbox_main),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
                       FALSE, FALSE, 0);

    /* ---- Results frame ---- */
    GtkWidget *frame = gtk_frame_new("Results");
    gtk_box_pack_start(GTK_BOX(vbox_main), frame, TRUE, TRUE, 0);

    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(frame), scrolled);

    app->txt_results = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->txt_results), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->txt_results), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->txt_results), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->txt_results), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(app->txt_results), 8);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(app->txt_results), 8);
    gtk_container_add(GTK_CONTAINER(scrolled), app->txt_results);

    /* Seed the text view with a short usage hint */
    GtkTextBuffer *tbuf =
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->txt_results));
    gtk_text_buffer_set_text(tbuf,
        "Select the I2C bus number and press\n"
        "\"Authenticate & Read Device Info\" to:\n\n"
        "  1. Initialise the STSAFE-A120 on /dev/i2c-N\n"
        "  2. Verify the device certificate against the ST production CA\n"
        "  3. Prove device ownership via challenge-response (key slot 0)\n"
        "  4. Display the User NVM zone partition table (SPL05 layout)\n"
        "  5. Hex-dump User NVM zone 1 and zone 2 data\n\n"
        "Hardware requirements:\n"
        "  - STM32MP1 board with OpenSTLinux\n"
        "  - X-NUCLEO-ESE01A1 expansion board (STSAFE-A120)\n"
        "  - I2C enabled in the device tree (i2cdetect -y N should show 0x20)\n",
        -1);
}

/* -------------------------------------------------------------------------- */
/* Main entry point                                                            */
/* -------------------------------------------------------------------------- */

/**
 * @brief  Application entry point.
 * @param  argc  Argument count (forwarded to gtk_init).
 * @param  argv  Argument vector (forwarded to gtk_init).
 * @retval 0 on clean exit.
 */
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    AppState *app = g_new0(AppState, 1);
    g_mutex_init(&app->result_mutex);

    build_ui(app);
    gtk_widget_show_all(app->window);

    /* Hide spinner until first button click */
    gtk_widget_hide(app->spinner);

    gtk_main();

    g_mutex_clear(&app->result_mutex);
    g_free(app);

    return 0;
}
