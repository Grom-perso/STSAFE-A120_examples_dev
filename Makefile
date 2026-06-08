# ******************************************************************************
# STSAFE-A120 Examples — Linux / STM32MP1 Build System
# ******************************************************************************
#
# This Makefile builds all STSAFE-A120 example applications for Linux,
# targeting the STM32MP1 platform (Cortex-A7 running OpenSTLinux).
#
# Usage:
#   make                                    - Build all console examples
#   make EXAMPLE=01_Echo_loop              - Build a specific console example
#   make gtk_demo                           - Build the GTK3 graphical demo
#   make CROSS_COMPILE=arm-linux-gnueabihf- - Cross-compile for STM32MP1
#   make clean                              - Remove all build artefacts
#   make help                               - Show this help
#
# Prerequisites:
#   - STSELib submodule must be initialised:
#       git submodule update --init Middleware/STSELib
#   - OpenSSL development libraries:
#       (native)  sudo apt-get install libssl-dev
#       (Yocto)   Included in OpenSTLinux SDK sysroot
#   - GTK3 development libraries (gtk_demo target only):
#       (native)  sudo apt-get install libgtk-3-dev
#       (Yocto)   Included in OpenSTLinux SDK sysroot
#
# ******************************************************************************

REPO_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

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
#      CFLAGS, LDFLAGS, etc.  Do NOT pass CROSS_COMPILE in this case.
#
#   2. Generic cross-toolchain (e.g. Linaro, Debian):
#        make CROSS_COMPILE=arm-linux-gnueabihf-
#
ifeq ($(origin CC), default)
CC := $(CROSS_COMPILE)gcc
endif
ifeq ($(origin AR), default)
AR := $(CROSS_COMPILE)ar
endif
ifeq ($(origin STRIP), default)
STRIP := $(CROSS_COMPILE)strip
endif

ifeq ($(origin PKG_CONFIG), default)
PKG_CONFIG := $(CROSS_COMPILE)pkg-config
endif

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
PLATFORM_DIR   := $(REPO_ROOT)/Platform
STSELIB_DIR    := $(REPO_ROOT)/Middleware/STSELib
APPS_UTILS_DIR := $(REPO_ROOT)/Applications/Apps_utils
PROJECTS_DIR   := $(REPO_ROOT)/Applications/Projects
BUILD_DIR      := build

# ---------------------------------------------------------------------------
# List of all console example projects (excluding template and GTK demo)
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
    05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM

GTK_EXAMPLE := 06_GTK_Authentication_Demo

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
# Compiler flags
# ---------------------------------------------------------------------------
CFLAGS += \
    -Wall \
    -Wextra \
    -Wno-unused-parameter \
    -O2 \
    -g \
    -DOPENSSL_API_COMPAT=0x10101000L \
    $(INCLUDES)

# ---------------------------------------------------------------------------
# Linker flags
# ---------------------------------------------------------------------------
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
# ---------------------------------------------------------------------------
STSELIB_SRCS := $(shell find $(STSELIB_DIR) -name '*.c' 2>/dev/null)

# ---------------------------------------------------------------------------
# Sanity check: verify STSELib submodule is initialised
# ---------------------------------------------------------------------------
.PHONY: check_stselib
check_stselib:
	@if [ -z "$(STSELIB_SRCS)" ]; then \
		echo ""; \
		echo "ERROR: STSELib submodule is not initialised!"; \
		echo "       Please run: git submodule update --init Middleware/STSELib"; \
		echo ""; \
		exit 1; \
	fi

# ---------------------------------------------------------------------------
# Build targets — console examples
# ---------------------------------------------------------------------------
.PHONY: all clean $(ALL_EXAMPLES) gtk_demo example

all: check_stselib $(addprefix $(BUILD_DIR)/,$(TARGETS))

# Rule to build a single console example binary
$(BUILD_DIR)/%: check_stselib
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f "$(PROJECTS_DIR)/$*/main.c" ]; then \
		echo "ERROR: Project '$*' not found at $(PROJECTS_DIR)/$*/main.c"; \
		exit 1; \
	fi
	@echo "Building $* ..."
	$(CC) $(CFLAGS) \
		-I$(PROJECTS_DIR)/$* \
		$(PROJECTS_DIR)/$*/main.c \
		$(PLATFORM_SRCS) \
		$(STSELIB_SRCS) \
		-o $@ \
		$(LDFLAGS)
	@echo "  -> $@ built successfully"

# Convenience target: build a single example via EXAMPLE=<name>
example: check_stselib $(BUILD_DIR)/$(EXAMPLE)

# ---------------------------------------------------------------------------
# Build target — GTK3 graphical authentication demo
# ---------------------------------------------------------------------------
#
# Extra flags are obtained via pkg-config so they correctly pick up the
# sysroot paths when cross-compiling with the OpenSTLinux SDK.
#
GTK_CFLAGS  := $(shell $(PKG_CONFIG) --cflags gtk+-3.0 2>/dev/null)
GTK_LDFLAGS := $(shell $(PKG_CONFIG) --libs   gtk+-3.0 2>/dev/null)

gtk_demo: check_stselib
	@if [ -z "$(GTK_CFLAGS)" ]; then \
		echo ""; \
		echo "ERROR: GTK+ 3 development files not found!"; \
		echo "       Native build:        sudo apt-get install libgtk-3-dev"; \
		echo "       Cross-compilation:   source the OpenSTLinux SDK (includes GTK3)"; \
		echo ""; \
		exit 1; \
	fi
	@mkdir -p $(BUILD_DIR)
	@echo "Building $(GTK_EXAMPLE) (GTK3 graphical demo) ..."
	$(CC) $(CFLAGS) $(GTK_CFLAGS) \
		-I$(PROJECTS_DIR)/$(GTK_EXAMPLE) \
		$(PROJECTS_DIR)/$(GTK_EXAMPLE)/main.c \
		$(PLATFORM_SRCS) \
		$(STSELIB_SRCS) \
		-o $(BUILD_DIR)/$(GTK_EXAMPLE) \
		$(LDFLAGS) $(GTK_LDFLAGS) -lpthread
	@echo "  -> $(BUILD_DIR)/$(GTK_EXAMPLE) built successfully"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
.PHONY: help
help:
	@echo ""
	@echo "STSAFE-A120 Examples — Linux/STM32MP1 Build System"
	@echo "===================================================="
	@echo ""
	@echo "Targets:"
	@echo "  all              Build all console examples (default)"
	@echo "  gtk_demo         Build the GTK3 graphical authentication demo"
	@echo "  EXAMPLE=<name>   Build a specific console example"
	@echo "  clean            Remove all build artefacts"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Workflows:"
	@echo ""
	@echo "  OpenSTLinux SDK (recommended for STM32MP1):"
	@echo "    source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi"
	@echo "    make            # all console examples"
	@echo "    make gtk_demo   # GTK3 graphical demo"
	@echo "    -- The SDK sets CC with --sysroot automatically. Do NOT pass CROSS_COMPILE."
	@echo ""
	@echo "  Generic cross-toolchain:"
	@echo "    make CROSS_COMPILE=arm-linux-gnueabihf-"
	@echo "    make CROSS_COMPILE=arm-linux-gnueabihf- gtk_demo"
	@echo ""
	@echo "Variables:"
	@echo "  CROSS_COMPILE    Toolchain prefix (NOT needed with OpenSTLinux SDK)"
	@echo "  PKG_CONFIG       pkg-config binary (default: \$(CROSS_COMPILE)pkg-config)"
	@echo "  EXAMPLE          Build only the specified console example"
	@echo ""
	@echo "Available console examples:"
	@$(foreach ex,$(ALL_EXAMPLES),echo "  $(ex)";)
	@echo ""
	@echo "Available graphical examples:"
	@echo "  $(GTK_EXAMPLE)  (use 'make gtk_demo')"
	@echo ""
