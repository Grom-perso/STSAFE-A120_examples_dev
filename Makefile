# ******************************************************************************
# STSAFE-A120 Examples - Linux / STM32MP1 Build System
# ******************************************************************************
#
# This Makefile builds all STSAFE-A120 example applications for Linux,
# targeting the STM32MP1 platform (Cortex-A7 running OpenSTLinux).
#
# Usage:
#   make                          - Build all examples (native)
#   make EXAMPLE=01_Echo_loop     - Build a specific example
#   make CROSS_COMPILE=arm-linux-gnueabihf-  - Cross-compile for STM32MP1
#   make clean                    - Remove all build artifacts
#
# Prerequisites:
#   - STSELib submodule must be initialized:
#       git submodule update --init Middleware/STSELib
#   - OpenSSL development libraries must be installed:
#       (native)  sudo apt-get install libssl-dev
#       (Yocto)   Included in OpenSTLinux SDK
#
# ******************************************************************************

REPO_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Ensure the default goal is 'all', regardless of rule ordering below.
.DEFAULT_GOAL := all

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
# Two supported workflows:
#
#   1. OpenSTLinux SDK (recommended for STM32MP1):
#        source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
#        make
#      The SDK environment-setup script exports CC (with --sysroot, -march, etc.),
#      CFLAGS, LDFLAGS, etc.  Do NOT pass CROSS_COMPILE in this case — the SDK
#      has already set CC correctly.
#
#   2. Generic cross-toolchain (e.g. Linaro, Debian):
#        make CROSS_COMPILE=arm-linux-gnueabihf-
#
# If CC is already set in the environment (origin != "default"), honour it
# unchanged so that the SDK sysroot flags are preserved.
ifeq ($(origin CC), default)
CC := $(CROSS_COMPILE)gcc
endif
ifeq ($(origin AR), default)
AR := $(CROSS_COMPILE)ar
endif
ifeq ($(origin STRIP), default)
STRIP := $(CROSS_COMPILE)strip
endif

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
PLATFORM_DIR   := $(REPO_ROOT)/Platform
STSELIB_DIR    := $(REPO_ROOT)/Middleware/STSELib
APPS_UTILS_DIR := $(REPO_ROOT)/Applications/Apps_utils
PROJECTS_DIR   := $(REPO_ROOT)/Applications/Projects
ENGINE_DIR     := $(REPO_ROOT)/Engine
BUILD_DIR      := build

# ---------------------------------------------------------------------------
# List of all example projects (excluding template)
# ---------------------------------------------------------------------------
ALL_EXAMPLES := \
    01_Echo_loop \
    01_Random_number \
    01_Hash \
    01_Device_authentication \
    01_Device_authentication_multi_steps \
    01_Key_pair_generation_NIST_P256 \
    01_Key_pair_generation_NIST_P521 \
    01_Key_pair_generation_BRAINPOOL_P512 \
    01_Key_pair_generation_EDWARDS_25519 \
    01_Secure_data_storage_zone_access \
    01_Secure_data_storage_counter_access \
    02_Command_AC_provisioning \
    02_Host_key_provisioning \
    02_Host_key_provisioning_wrapped \
    03_ECDH \
    03_Key_wrapping \
    04_Symmetric_key_provisioning_control_fields \
    05_Symmetric_key_establishment_compute_AES-128_CMAC \
    05_Symmetric_key_establishment_encrypt_AES-256_CCM \
    05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC \
    05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM \
    06_TLS_client

# If EXAMPLE is specified on the command line, build only that one
ifdef EXAMPLE
TARGETS := $(EXAMPLE)
else
TARGETS := $(ALL_EXAMPLES)
endif

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------
INCLUDES := \
    -I$(PLATFORM_DIR) \
    -I$(PLATFORM_DIR)/STSELib \
    -I$(STSELIB_DIR) \
    -I$(APPS_UTILS_DIR)

# ---------------------------------------------------------------------------
# Preprocessor definitions
#
# Enable all supported ECC curves and hash algorithms so that each example
# can select what it needs via its own stse_conf.h.
# The crypto feature flags below match what is needed across the full example
# set; individual examples that do not use a feature simply leave it uncalled.
# ---------------------------------------------------------------------------
# DEFINES := \
#     -DSTSE_CONF_STSAFE_A_SUPPORT \
#     -DSTSE_CONF_ECC_NIST_P_256 \
#     -DSTSE_CONF_ECC_NIST_P_384 \
#     -DSTSE_CONF_ECC_NIST_P_521 \
#     -DSTSE_CONF_ECC_BRAINPOOL_P_256 \
#     -DSTSE_CONF_ECC_BRAINPOOL_P_384 \
#     -DSTSE_CONF_ECC_BRAINPOOL_P_512 \
#     -DSTSE_CONF_ECC_CURVE_25519 \
#     -DSTSE_CONF_ECC_EDWARD_25519 \
#     -DSTSE_CONF_HASH_SHA_1 \
#     -DSTSE_CONF_HASH_SHA_224 \
#     -DSTSE_CONF_HASH_SHA_256 \
#     -DSTSE_CONF_HASH_SHA_384 \
#     -DSTSE_CONF_HASH_SHA_512 \
#     -DSTSE_CONF_USE_HOST_KEY_ESTABLISHMENT \
#     -DSTSE_CONF_USE_HOST_SESSION \
#     -DSTSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT \
#     -DSTSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED \
#     -DSTSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED

# ---------------------------------------------------------------------------
# Compiler flags
# ---------------------------------------------------------------------------
# OPENSSL_API_COMPAT: Suppress deprecation warnings for APIs available in
# OpenSSL 1.1.1, which remain functional in OpenSSL 3.x. This ensures the
# same source compiles cleanly on both OpenSSL 1.1.x (OpenSTLinux SDK) and
# OpenSSL 3.x (recent host distributions).
#
# Using += so that any --sysroot, -march, -mfpu, -mfloat-abi flags injected
# by the OpenSTLinux SDK environment-setup script are preserved.
CFLAGS += \
    -Wall \
    -Wextra \
    -Wno-unused-parameter \
    -O2 \
    -g \
    -DOPENSSL_API_COMPAT=0x10101000L \
    $(INCLUDES) \
    $(DEFINES)

# ---------------------------------------------------------------------------
# Linker flags
# ---------------------------------------------------------------------------
# Using += to preserve --sysroot and rpath flags from the SDK environment.
LDFLAGS += -lssl -lcrypto -lm

# ---------------------------------------------------------------------------
# Platform source files (shared across all examples)
# ---------------------------------------------------------------------------
PLATFORM_SRCS := \
    $(PLATFORM_DIR)/STSELib/stse_platform_i2c.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_delay.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_aes.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_ecc.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_hash.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_random.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_crc.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_crypto_init.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_power.c \
    $(APPS_UTILS_DIR)/Apps_utils.c

# ---------------------------------------------------------------------------
# STSELib source files (from submodule)
# Discover all .c files in the library directory tree.
# The sal/pkcs11/ sources are excluded from the general example builds because
# they require STSE_CONF_ECC_* and STSE_CONF_HASH_* feature flags that are
# not universally defined in every example's stse_conf.h.  The engine and
# pkcs11 module targets use STSELIB_ENGINE_SRCS which includes all files
# (sal/pkcs11/ is not filtered out there) together with the engine's own
# stse_conf.h that enables the required feature flags.
# ---------------------------------------------------------------------------
STSELIB_SRCS := $(filter-out $(STSELIB_DIR)/sal/%,\
    $(shell find $(STSELIB_DIR) -name '*.c' 2>/dev/null))

# STSELib sources for the engine / pkcs11 builds — same discovery as above
# but WITHOUT the sal/pkcs11 filter, so the PKCS#11 SAL layer is included.
STSELIB_ENGINE_SRCS := $(shell find $(STSELIB_DIR) -name '*.c' 2>/dev/null)

# ---------------------------------------------------------------------------
# Sanity check: verify STSELib submodule is initialized
# ---------------------------------------------------------------------------
.PHONY: check_stselib
check_stselib:
	@if [ -z "$(STSELIB_SRCS)" ]; then \
		echo ""; \
		echo "ERROR: STSELib submodule is not initialized!"; \
		echo "       Please run: git submodule update --init Middleware/STSELib"; \
		echo ""; \
		exit 1; \
	fi

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------
.PHONY: all clean engine pkcs11 tls_dynamic example $(ALL_EXAMPLES)

all: check_stselib $(addprefix $(BUILD_DIR)/,$(TARGETS))

# Rule to build a single example binary.
# Compiles all *.c files found in the project directory so that examples
# with multiple source files (e.g. 06_TLS_client with its engine) are handled
# automatically alongside the single-file examples.
$(BUILD_DIR)/%: check_stselib
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f "$(PROJECTS_DIR)/$*/main.c" ]; then \
		echo "ERROR: Project '$*' not found at $(PROJECTS_DIR)/$*/main.c"; \
		exit 1; \
	fi
	@echo "Building $* ..."
	$(CC) $(CFLAGS) \
		-I$(PROJECTS_DIR)/$* \
		$(wildcard $(PROJECTS_DIR)/$*/*.c) \
		$(PLATFORM_SRCS) \
		$(STSELIB_SRCS) \
		-o $@ \
		$(LDFLAGS)
	@echo "  -> $@ built successfully"

# ---------------------------------------------------------------------------
# Shared-library engine target
#
# Builds the dynamically-loadable OpenSSL engine backed by the PKCS#11 layer:
#   build/libstsafe_engine.so
#
# The engine uses the PKCS#11 SAL layer from STSELib (sal/pkcs11/) internally
# instead of calling STSELib functions directly.
#
# The .so can then be loaded by OpenSSL at runtime via:
#   export OPENSSL_CONF=Engine/openssl-stsafe.cnf
#   openssl engine -v -t stsafe
#
# The Engine/ directory contains its own stse_conf.h (included via
# -I$(ENGINE_DIR)) which configures the STSELib feature set for the
# shared library.
#
# Platform sources are compiled with -fPIC because position-independent
# code is mandatory for shared libraries.  The APPS_UTILS_DIR sources are
# NOT included here (they reference UART/terminal helpers not needed in
# the engine).
# ---------------------------------------------------------------------------
ENGINE_PLATFORM_SRCS := \
	$(PLATFORM_DIR)/STSELib/stse_platform_i2c.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_delay.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_aes.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_ecc.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_hash.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_random.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_crc.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_crypto_init.c \
	$(PLATFORM_DIR)/STSELib/stse_platform_power.c

# PKCS#11 SAL layer sources (new in Grom-perso/STSELib-dev@feature/pkcs11).
# NOTE: these are already included in STSELIB_ENGINE_SRCS (via find, unfiltered),
# so they are listed here only for reference.
PKCS11_SRCS := \
	$(STSELIB_DIR)/sal/pkcs11/stse_pkcs11.c \
	$(STSELIB_DIR)/sal/pkcs11/stse_cryptoki.c

# The engine source is only the engine wrapper; STSELib (including the PKCS#11
# SAL layer) is pulled in via STSELIB_SRCS.
ENGINE_SRCS := \
	$(ENGINE_DIR)/stsafe_engine_so.c \
	$(ENGINE_PLATFORM_SRCS)

ENGINE_CFLAGS := \
	-shared -fPIC \
	-Wall -Wextra -Wno-unused-parameter \
	-O2 -g \
	-DOPENSSL_API_COMPAT=0x10101000L \
	-I$(ENGINE_DIR) \
	-I$(PLATFORM_DIR) \
	-I$(PLATFORM_DIR)/STSELib \
	-I$(STSELIB_DIR)

.PHONY: engine
engine: check_stselib $(BUILD_DIR)/libstsafe_engine.so

$(BUILD_DIR)/libstsafe_engine.so: check_stselib
	@mkdir -p $(BUILD_DIR)
	@echo "Building dynamic engine (libstsafe_engine.so, PKCS#11-backed) ..."
	$(CC) $(ENGINE_CFLAGS) \
		$(ENGINE_SRCS) \
		$(STSELIB_ENGINE_SRCS) \
		-o $@ \
		-lssl -lcrypto -lm
	@echo "  -> $@ built successfully"
	@echo ""
	@echo "  To use the engine:"
	@echo "    export OPENSSL_CONF=$(REPO_ROOT)/Engine/openssl-stsafe.cnf"
	@echo "    openssl engine -v -t stsafe"

# ---------------------------------------------------------------------------
# Standalone PKCS#11 module target
#
# Builds a proper PKCS#11 module that exports C_GetFunctionList:
#   build/libstsafe_pkcs11.so
#
# This module can be used with any PKCS#11-aware application:
#   - libp11 / pkcs11-helper bridge for OpenSSL (libpkcs11.so)
#   - OpenSSL 3.x pkcs11-provider (external)
#   - strongSwan, OpenVPN, Firefox NSS, etc.
#
# Usage with OpenSSL 1.1.x / libp11 engine:
#   OPENSSL_CONF=Engine/openssl-stsafe-pkcs11.cnf openssl engine pkcs11
#
# Usage with openssl s_client via pkcs11-provider (OpenSSL 3.x):
#   openssl s_client -provider pkcs11 \
#     -key "pkcs11:token=STSAFE-A120;object=0" -connect <server>:443
# ---------------------------------------------------------------------------
PKCS11_MODULE_PLATFORM_SRCS := \
	$(ENGINE_PLATFORM_SRCS)

PKCS11_MODULE_CFLAGS := \
	-shared -fPIC \
	-Wall -Wextra -Wno-unused-parameter \
	-O2 -g \
	-I$(ENGINE_DIR) \
	-I$(PLATFORM_DIR) \
	-I$(PLATFORM_DIR)/STSELib \
	-I$(STSELIB_DIR)

.PHONY: pkcs11
pkcs11: check_stselib $(BUILD_DIR)/libstsafe_pkcs11.so

$(BUILD_DIR)/libstsafe_pkcs11.so: check_stselib
	@mkdir -p $(BUILD_DIR)
	@echo "Building standalone PKCS#11 module (libstsafe_pkcs11.so) ..."
	$(CC) $(PKCS11_MODULE_CFLAGS) \
		$(PKCS11_MODULE_PLATFORM_SRCS) \
		$(STSELIB_ENGINE_SRCS) \
		-o $@ \
		-lm
	@echo "  -> $@ built successfully"
	@echo ""
	@echo "  To use with libp11 / pkcs11 ENGINE:"
	@echo "    OPENSSL_CONF=Engine/openssl-stsafe-pkcs11.cnf openssl engine pkcs11"
	@echo ""
	@echo "  To use C_GetFunctionList directly from any PKCS#11 application:"
	@echo "    dlopen(\"build/libstsafe_pkcs11.so\", RTLD_NOW)"

# Convenience target: build a single example via EXAMPLE=<name>
.PHONY: example
example: check_stselib $(BUILD_DIR)/$(EXAMPLE)

# ---------------------------------------------------------------------------
# Dynamic-engine variant of the TLS client
#
# Builds 06_TLS_client with -DSTSAFE_USE_DYNAMIC_ENGINE so it loads the
# STSAFE engine from build/libstsafe_engine.so at runtime instead of having
# the engine compiled directly into the binary.
#
# Run it with:
#   export OPENSSL_CONF=$(REPO_ROOT)/Engine/openssl-stsafe.cnf
#   ./build/06_TLS_client_dynamic
# ---------------------------------------------------------------------------
.PHONY: tls_dynamic
tls_dynamic: check_stselib $(BUILD_DIR)/libstsafe_engine.so \
             $(BUILD_DIR)/06_TLS_client_dynamic

$(BUILD_DIR)/06_TLS_client_dynamic: check_stselib
	@mkdir -p $(BUILD_DIR)
	@echo "Building 06_TLS_client (dynamic engine mode) ..."
	$(CC) $(CFLAGS) \
		-DSTSAFE_USE_DYNAMIC_ENGINE \
		-DSTSAFE_ENGINE_SO_PATH=\"build/libstsafe_engine.so\" \
		-I$(PROJECTS_DIR)/06_TLS_client \
		$(PROJECTS_DIR)/06_TLS_client/main.c \
		$(PLATFORM_SRCS) \
		$(STSELIB_SRCS) \
		-o $@ \
		$(LDFLAGS)
	@echo "  -> $@ built successfully"
	@echo ""
	@echo "  Run with:"
	@echo "    export OPENSSL_CONF=$(REPO_ROOT)/Engine/openssl-stsafe.cnf"
	@echo "    $@"

clean:
	rm -rf $(BUILD_DIR)

# ---------------------------------------------------------------------------
# Help target
# ---------------------------------------------------------------------------
.PHONY: help
help:
	@echo ""
	@echo "STSAFE-A120 Examples - Linux/STM32MP1 Build System"
	@echo "===================================================="
	@echo ""
	@echo "Targets:"
	@echo "  all              Build all examples (default)"
	@echo "  engine           Build the PKCS#11-backed OpenSSL ENGINE (.so)"
	@echo "                   (output: build/libstsafe_engine.so)"
	@echo "  pkcs11           Build the standalone PKCS#11 module (.so)"
	@echo "                   (output: build/libstsafe_pkcs11.so)"
	@echo "  tls_dynamic      Build TLS client in dynamic-engine mode"
	@echo "  EXAMPLE=<name>   Build a specific example"
	@echo "  clean            Remove all build artifacts"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Workflows:"
	@echo ""
	@echo "  OpenSTLinux SDK (recommended for STM32MP1):"
	@echo "    source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi"
	@echo "    make"
	@echo "    -- The SDK sets CC with --sysroot automatically. Do NOT pass CROSS_COMPILE."
	@echo ""
	@echo "  Generic cross-toolchain:"
	@echo "    make CROSS_COMPILE=arm-linux-gnueabihf-"
	@echo ""
	@echo "Variables:"
	@echo "  CROSS_COMPILE    Toolchain prefix for generic toolchains (NOT needed with OpenSTLinux SDK)"
	@echo "  EXAMPLE          Build only the specified example (e.g. 01_Echo_loop)"
	@echo ""
	@echo "OpenSSL ENGINE (PKCS#11-backed, for openssl CLI and TLS apps):"
	@echo "  make engine          Build build/libstsafe_engine.so"
	@echo "  make tls_dynamic     Build the TLS client in dynamic-engine mode"
	@echo "  export OPENSSL_CONF=Engine/openssl-stsafe.cnf"
	@echo "  openssl engine -v -t stsafe          # verify loading"
	@echo "  openssl s_client -engine stsafe \\"
	@echo "    -keyform ENGINE -key \"0\" -connect <server>:443"
	@echo ""
	@echo "Available examples:"
	@$(foreach ex,$(ALL_EXAMPLES),echo "  $(ex)";)
	@echo ""
