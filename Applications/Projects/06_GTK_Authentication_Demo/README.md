# STSAFE-A120 GTK3 Authentication Demo

Graphical authentication and NVM data inspection example for the STSAFE-A120 secure element running on **STM32MP1 / OpenSTLinux** (Linux MPU).

## Overview

This example provides a **GTK3 desktop application** that lets the user:

| # | Action |
|---|--------|
| 1 | Initialise the STSAFE-A120 on the selected I2C bus |
| 2 | Verify the device certificate chain against the ST production CA (SPL05) |
| 3 | Prove device ownership via ECDSA challenge-response (static key slot 0) |
| 4 | Display the full User NVM zone partition table |
| 5 | Hex-dump User NVM zone 1 and zone 2 data |

A single button press triggers all five steps concurrently in a background thread,
keeping the GTK main loop responsive.  Results are shown in the application window
colour-coded by outcome (green = authenticated, red = failed).

### STSAFE-A120 SPL05 User NVM Zone Layout

| Zone | Contents              | Size    | Read access | Write access |
|------|-----------------------|---------|-------------|--------------|
| 0    | Device certificate    | ~500 B  | ALWAYS      | NEVER        |
| 1    | User NVM data 1       | 100 B   | ALWAYS      | ALWAYS       |
| 2    | User NVM data 2       | 100 B   | ALWAYS      | ALWAYS       |

> **Note**: The exact sizes and access conditions are queried at runtime from the
> device so the application adapts to any SPL personalization automatically.

---

## Hardware Prerequisites

| Component | Notes |
|-----------|-------|
| STM32MP157C-DK2 (or compatible STM32MP1 board) | Running OpenSTLinux |
| X-NUCLEO-ESE01A1 expansion board | STSAFE-A120, plugs into the Arduino connector |

The STSAFE-A120 default I2C address is **0x20**.  The Arduino connector on
STM32MP157-DK2 maps to **I2C5** (bus number may vary — see troubleshooting).

---

## Software Prerequisites

| Dependency | Version | Notes |
|-----------|---------|-------|
| OpenSTLinux SDK | ≥ 3.1 | Provides cross-toolchain + sysroot (OpenSSL + GTK3) |
| GTK+ 3 | ≥ 3.22 | Included in the OpenSTLinux distribution |
| OpenSSL | ≥ 1.1.1 | Cryptographic backend for STSELib |
| STSELib | latest | Git submodule — see "Initialise submodule" below |

---

## Building

### 1. Initialise the STSELib submodule (repository root)

```bash
git submodule update --init Middleware/STSELib
```

### 2. Source the OpenSTLinux SDK (cross-compilation)

```bash
source /opt/st/stm32mp1/<version>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
```

> **Important**: The SDK environment sets `CC` with `--sysroot` and hardware
> float flags already.  Do **not** pass `CROSS_COMPILE=` when using the SDK.

### 3. Build

From the **repository root** (where the top-level `Makefile` lives):

```bash
make EXAMPLE=06_GTK_Authentication_Demo
```

The binary is placed in `build/06_GTK_Authentication_Demo`.

#### Build for native execution on the board

If you have a shell directly on the board:

```bash
# Install build dependencies (OpenSTLinux / Debian-based)
sudo apt-get install libgtk-3-dev libssl-dev

# Build natively
make EXAMPLE=06_GTK_Authentication_Demo
```

---

## Running

### 1. Transfer the binary to the board

```bash
scp build/06_GTK_Authentication_Demo root@<board-ip>:/home/root/
```

### 2. Check the I2C bus number

```bash
i2cdetect -l                  # list buses
i2cdetect -y -r <bus>         # scan; STSAFE-A120 should appear at 0x20
```

Update the **I2C bus ID** spin-button in the application (default: 1) to match
the bus number shown above.

### 3. Set up the display (Weston / Wayland or X11)

The OpenSTLinux Weston compositor is the default display server.

```bash
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/run/user/$(id -u)
./06_GTK_Authentication_Demo
```

For X11 environments:

```bash
export DISPLAY=:0
./06_GTK_Authentication_Demo
```

### 4. Using the application

1. Select the correct **I2C bus ID** with the spin button.
2. Click **Authenticate & Read Device Info**.
3. The button is disabled and an activity spinner appears while operations run.
4. When complete, the **status banner** turns green (✓ AUTHENTICATED) or red
   (✗ AUTHENTICATION FAILED).
5. The **results pane** shows the full partition table and hex-dumped zone data.

---

## Troubleshooting

### STSAFE-A120 not detected on I2C

```
ERROR: stse_init (0x0001)
Check that /dev/i2c-N is accessible…
```

* Run `i2cdetect -l` and `i2cdetect -y <bus>` to find the correct bus number.
* On STM32MP157-DK2 the Arduino I2C5 may be **disabled** in the default device tree.
  See the *ReadMe.md* at the repository root for device-tree patching instructions.
* Ensure `/dev/i2c-N` is readable:

```bash
sudo chmod 666 /dev/i2c-<N>
# or add your user to the i2c group:
sudo usermod -a -G i2c $USER
```

### GTK window does not appear

* Make sure `WAYLAND_DISPLAY` (or `DISPLAY`) and `XDG_RUNTIME_DIR` are set.
* On systems with Weston running as root, connect as root or set the appropriate
  permissions on the Wayland socket.

### Missing GTK3 libraries during build

```
Package gtk+-3.0 was not found
```

* Native build: `sudo apt-get install libgtk-3-dev`
* Cross-compilation: the OpenSTLinux SDK sysroot includes GTK3 development files.
  Ensure the SDK environment is sourced correctly before running `make`.

---

## Code Structure

```
Applications/Projects/06_GTK_Authentication_Demo/
├── main.c       ← GTK3 application (authentication + data display)
├── stse_conf.h  ← STSAFE-A library configuration (NIST-P256, SHA-256)
└── README.md    ← This file
```

The application links against:

* **STSELib** — secure element abstraction library (submodule)
* **Platform** — Linux platform driver layer (I2C, delays, RNG, crypto)
* **OpenSSL** (`libssl`, `libcrypto`) — ECC and hash operations
* **GTK+ 3** — graphical user interface

---

*Copyright © 2022 STMicroelectronics – Licensed under the terms in LICENSE.txt*
