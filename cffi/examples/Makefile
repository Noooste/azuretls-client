# Examples Makefile for AzureTLS CFFI

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Platform-specific settings
ifeq ($(GOOS),windows)
    EXT := .dll
    EXE_EXT := .exe
else ifeq ($(GOOS),darwin)
    EXT := .dylib
    EXE_EXT :=
else
    EXT := .so
    EXE_EXT :=
endif

# Library name
LIB_NAME := libazuretls_$(GOOS)_$(GOARCH)$(EXT)
LIB_PATH := ../build/$(LIB_NAME)

# Compiler settings
CC := gcc
CFLAGS := -Wall -Wextra -std=c99 -I..
LDFLAGS := -L../build -lazuretls_$(GOOS)_$(GOARCH)

# Targets
C_EXAMPLE := c_example$(EXE_EXT)
PYTHON_EXAMPLE := python_example.py

.PHONY: all clean test test-c test-python

all: $(C_EXAMPLE)

# Build C example
$(C_EXAMPLE): c_example.c $(LIB_PATH)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Test targets
test: test-c test-python

test-c: $(C_EXAMPLE)
	@echo "Testing C example..."
ifeq ($(GOOS),windows)
	@set PATH=../build;%PATH% && ./$(C_EXAMPLE)
else ifeq ($(GOOS),darwin)
	@DYLD_LIBRARY_PATH=../build ./$(C_EXAMPLE)
else
	@LD_LIBRARY_PATH=../build ./$(C_EXAMPLE)
endif

test-python: $(PYTHON_EXAMPLE)
	@echo "Testing Python example..."
ifeq ($(GOOS),windows)
	@set PATH=../build;%PATH% && python $(PYTHON_EXAMPLE)
else
	@LD_LIBRARY_PATH=../build:$$LD_LIBRARY_PATH DYLD_LIBRARY_PATH=../build:$$DYLD_LIBRARY_PATH python3 $(PYTHON_EXAMPLE)
endif

# Check if library exists
$(LIB_PATH):
	@echo "Library not found: $(LIB_PATH)"
	@echo "Please run 'make' in the parent directory first"
	@exit 1

# Clean
clean:
	rm -f $(C_EXAMPLE)

# Help
help:
	@echo "AzureTLS CFFI Examples"
	@echo ""
	@echo "Targets:"
	@echo "  all        Build all examples"
	@echo "  test       Run all tests"
	@echo "  test-c     Run C example"
	@echo "  test-python Run Python example"
	@echo "  clean      Remove built examples"
	@echo "  help       Show this help"
	@echo ""
	@echo "Current platform: $(GOOS)/$(GOARCH)"
	@echo "Expected library: $(LIB_PATH)"