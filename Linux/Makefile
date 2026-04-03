################################################################################
# Linux/Makefile
# Build system for STSAFE-A120 Linux examples and engine.
#
# Targets:
#   make              – build all examples
#   make all          – same as above
#   make engine       – build the STSAFE OpenSSL dynamic engine
#   make cli          – build the stse_verify CLI tool
#   make 06_TLS_client         – build TLS client example
#   make 07_Matter_attestation – build Matter attestation example
#   make clean        – remove build artefacts
#
# Variables:
#   CROSS_COMPILE – toolchain prefix (e.g. arm-linux-gnueabihf-)
#   SYSROOT       – optional sysroot for cross-compilation
#   EXAMPLE       – build a single example (e.g. make EXAMPLE=06_TLS_client)
#
# OpenSTLinux SDK workflow:
#   source <sdk>/environment-setup-...
#   make
################################################################################

SHELL := /bin/bash

# --------------------------------------------------------------------------
# Toolchain
# --------------------------------------------------------------------------

ifeq ($(origin CC),default)
    CC := $(CROSS_COMPILE)gcc
endif

AR         ?= $(CROSS_COMPILE)ar
PKG_CONFIG ?= $(CROSS_COMPILE)pkg-config

ifdef SYSROOT
    SYSROOT_FLAGS := --sysroot=$(SYSROOT)
endif

# --------------------------------------------------------------------------
# Directories
# --------------------------------------------------------------------------

ROOT_DIR   := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))..
BUILD_DIR  := $(ROOT_DIR)/Linux/build

MIDDLEWARE_DIR := $(ROOT_DIR)/Middleware/STSELib
PLATFORM_DIR   := $(ROOT_DIR)/Platform_Portable

PROJECTS_DIR := $(ROOT_DIR)/Applications/Projects
CLI_DIR      := $(ROOT_DIR)/Applications/CLI
ENGINE_DIR   := $(ROOT_DIR)/Engine
MATTER_DIR   := $(ROOT_DIR)/Middleware/Matter

# --------------------------------------------------------------------------
# Compiler flags
# --------------------------------------------------------------------------

CFLAGS += $(SYSROOT_FLAGS)
CFLAGS += -Wall -Wextra -Wno-unused-parameter
CFLAGS += -I$(ROOT_DIR)
CFLAGS += -I$(ROOT_DIR)/Middleware/STSELib
CFLAGS += -I$(PLATFORM_DIR)
CFLAGS += -I$(PLATFORM_DIR)/STSELib
CFLAGS += -DSTSE_CONF_STSAFE_A_SUPPORT
CFLAGS += -DSTSE_CONF_ECC_NIST_P_256
CFLAGS += -DSTSE_CONF_HASH_SHA_256

LDFLAGS += $(SYSROOT_FLAGS)

# OpenSSL (required by engine and TLS client)
OPENSSL_CFLAGS  := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LDFLAGS := $(shell $(PKG_CONFIG) --libs   openssl 2>/dev/null)

# --------------------------------------------------------------------------
# STSELib and Platform_Portable sources
# --------------------------------------------------------------------------

STSELIB_SRCS := $(wildcard $(MIDDLEWARE_DIR)/*.c)

PLATFORM_SRCS := \
    $(PLATFORM_DIR)/stse_platform_portable.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_i2c.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_delay.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_random.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_crc.c \
    $(PLATFORM_DIR)/STSELib/stse_platform_power.c

MATTER_SRCS := $(MATTER_DIR)/stse_matter.c

COMMON_SRCS := $(STSELIB_SRCS) $(PLATFORM_SRCS)

# --------------------------------------------------------------------------
# List of example projects
# --------------------------------------------------------------------------

EXAMPLES := $(notdir $(wildcard $(PROJECTS_DIR)/0*))

ifdef EXAMPLE
    EXAMPLES := $(EXAMPLE)
endif

EXAMPLE_TARGETS := $(addprefix $(BUILD_DIR)/,$(EXAMPLES))

# --------------------------------------------------------------------------
# Default target
# --------------------------------------------------------------------------

.PHONY: all
all: $(EXAMPLE_TARGETS) $(BUILD_DIR)/stse_verify

# --------------------------------------------------------------------------
# Generic example build rule (re-defined specifically for special targets)
# --------------------------------------------------------------------------

$(BUILD_DIR)/%: $(PROJECTS_DIR)/%/main.c $(COMMON_SRCS) $(MATTER_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) \
	    -I$(PROJECTS_DIR)/$* \
	    $^ \
	    -o $@ \
	    $(LDFLAGS) -lpthread

# TLS client needs OpenSSL
$(BUILD_DIR)/06_TLS_client: $(PROJECTS_DIR)/06_TLS_client/main.c $(COMMON_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) \
	    -I$(PROJECTS_DIR)/06_TLS_client \
	    $^ \
	    -o $@ \
	    $(LDFLAGS) $(OPENSSL_LDFLAGS) -lpthread

# --------------------------------------------------------------------------
# OpenSSL dynamic engine
# --------------------------------------------------------------------------

.PHONY: engine
engine: $(BUILD_DIR)/libstsafe_engine.so

ENGINE_SRCS := $(ENGINE_DIR)/stsafe_engine_so.c \
               $(PLATFORM_DIR)/stse_platform_portable.c \
               $(STSELIB_SRCS)

$(BUILD_DIR)/libstsafe_engine.so: $(ENGINE_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) \
	    -fPIC -shared \
	    -I$(PROJECTS_DIR)/06_TLS_client \
	    $^ \
	    -o $@ \
	    $(LDFLAGS) $(OPENSSL_LDFLAGS)

# --------------------------------------------------------------------------
# CLI verification tool
# --------------------------------------------------------------------------

.PHONY: cli
cli: $(BUILD_DIR)/stse_verify

CLI_SRCS := $(CLI_DIR)/stse_verify.c \
            $(COMMON_SRCS)

$(BUILD_DIR)/stse_verify: $(CLI_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) \
	    -DSTSE_VERIFY_USE_OPENSSL \
	    $^ \
	    -o $@ \
	    $(LDFLAGS) $(OPENSSL_LDFLAGS) -lpthread

# --------------------------------------------------------------------------
# Clean
# --------------------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
