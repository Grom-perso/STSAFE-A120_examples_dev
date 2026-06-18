# STSAFE-A Software Development Kit (OpenSTDroid Userspace)

The **STSAFE-A120 example package** provides application examples demonstrating how to use STSAFE-A120 from **OpenSTDroid userspace**.

These examples are reference integrations of:
- **STSELib** (secure element middleware)
- **OpenSSL** (host cryptographic backend)
- **Linux userspace I2C** access (`/dev/i2c-*`)

---

## Scope

This branch is dedicated to **OpenSTDroid-only userspace integration**.

It intentionally focuses on Linux/OpenSTDroid workflows and runtime behavior.

---

## Repository Layout

- `Applications/Projects/` — STSAFE-A120 example applications
- `Applications/Apps_utils/` — common app utility helpers
- `Platform/STSELib/` — OpenSTDroid/Linux platform adaptation layer
- `Middleware/STSELib/` — STSELib submodule
- `Makefile` — root build entry point

---

## Prerequisites

### Host

- `git`
- `make`
- GCC toolchain (native or cross)
- OpenSSL development headers/libraries (`libssl-dev` equivalent)

### Target Runtime

- OpenSTDroid userspace environment
- Linux kernel with I2C enabled
- Access to `/dev/i2c-*`
- OpenSSL runtime libraries

---

## Setup

### 1) Clone

```bash
git clone https://github.com/Grom-perso/stsafe-a-sdk-dev.git
cd stsafe-a-sdk-dev
```

### 2) Initialize submodule

```bash
git submodule update --init Middleware/STSELib
```

---

## Build

### Build all examples

```bash
make
```

### Build one example

```bash
make EXAMPLE=01_Echo_loop
```

### Cross-compile (generic toolchain)

```bash
make CROSS_COMPILE=arm-linux-gnueabihf-
```

### Cross-compile one example

```bash
make CROSS_COMPILE=arm-linux-gnueabihf- EXAMPLE=01_Echo_loop
```

Build outputs are generated under:

```text
build/
```

---

## Run

### 1) Copy binary to target

```bash
scp build/01_Echo_loop root@<target-ip>:/home/root/
```

### 2) Verify I2C bus and permissions on target

```bash
ls /dev/i2c-*
i2cdetect -l
i2cdetect -y <bus-number>
```

If required:

```bash
sudo chmod 666 /dev/i2c-<bus-number>
```

### 3) Run example

```bash
./01_Echo_loop
```

---

## Build Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EXAMPLE` | *(all)* | Build only one example |
| `CROSS_COMPILE` | *(empty)* | Cross-toolchain prefix |

---

## Troubleshooting

### STSELib submodule missing

```text
ERROR: STSELib submodule is not initialized!
```

Fix:

```bash
git submodule update --init Middleware/STSELib
```

### OpenSSL headers missing

```text
fatal error: openssl/evp.h: No such file or directory
```

Fix (host): install OpenSSL development package (`libssl-dev` equivalent).

### I2C device not found or permission denied

- Confirm bus exists with `i2cdetect -l`
- Confirm STSAFE appears at expected address (typically `0x20`)
- Ensure process has access to `/dev/i2c-*`

---

## Additional Resources

- [STSAFE-A120 Product Page](https://www.st.com/en/secure-mcus/stsafe-a120.html)
- [X-NUCLEO-ESE01A1 Expansion Board](https://www.st.com/en/evaluation-tools/x-nucleo-ese01a1.html)
- [STSELib](https://github.com/STMicroelectronics/STSELib)

---

*Copyright © 2024 STMicroelectronics – Licensed under the terms found in the LICENSE file.*
