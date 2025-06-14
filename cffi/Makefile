# AzureTLS CFFI Makefile
# Supports Windows, Linux, macOS, and various architectures

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Output directory
BUILD_DIR := build

# Library name
LIB_NAME := azuretls

# Platform-specific settings
ifeq ($(GOOS),windows)
    EXT := .dll
    CGO_ENABLED := 1
else ifeq ($(GOOS),darwin)
    EXT := .dylib
    CGO_ENABLED := 1
else
    EXT := .so
    CGO_ENABLED := 1
endif

# Target library name
TARGET := $(BUILD_DIR)/lib$(LIB_NAME)_$(GOOS)_$(GOARCH)$(EXT)

# Go build flags
GO_BUILD_FLAGS := -buildmode=c-shared
GO_LDFLAGS := -s -w

# Default target
.PHONY: all
all: $(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build shared library
$(TARGET): $(BUILD_DIR) main.go
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(TARGET) main.go

# Build for all platforms
.PHONY: build-all
build-all: build-linux build-windows build-darwin

# Linux builds
.PHONY: build-linux
build-linux: build-linux-amd64 build-linux-arm64 build-linux-386 build-linux-arm

.PHONY: build-linux-amd64
build-linux-amd64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_linux_amd64.so main.go

.PHONY: build-linux-arm64
build-linux-arm64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_linux_arm64.so main.go

.PHONY: build-linux-386
build-linux-386: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=386 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_linux_386.so main.go

.PHONY: build-linux-arm
build-linux-arm: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=arm \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_linux_arm.so main.go

# Windows builds
.PHONY: build-windows
build-windows: build-windows-amd64 build-windows-386 build-windows-arm64

.PHONY: build-windows-amd64
build-windows-amd64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_windows_amd64.dll main.go

.PHONY: build-windows-386
build-windows-386: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=386 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_windows_386.dll main.go

.PHONY: build-windows-arm64
build-windows-arm64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=arm64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_windows_arm64.dll main.go

# macOS builds
.PHONY: build-darwin
build-darwin: build-darwin-amd64 build-darwin-arm64

.PHONY: build-darwin-amd64
build-darwin-amd64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_darwin_amd64.dylib main.go

.PHONY: build-darwin-arm64
build-darwin-arm64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_darwin_arm64.dylib main.go

# FreeBSD builds
.PHONY: build-freebsd
build-freebsd: build-freebsd-amd64 build-freebsd-arm64

.PHONY: build-freebsd-amd64
build-freebsd-amd64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=freebsd GOARCH=amd64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_freebsd_amd64.so main.go

.PHONY: build-freebsd-arm64
build-freebsd-arm64: $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=freebsd GOARCH=arm64 \
	go build $(GO_BUILD_FLAGS) \
	-ldflags="$(GO_LDFLAGS)" \
	-o $(BUILD_DIR)/lib$(LIB_NAME)_freebsd_arm64.so main.go

# Copy header file to build directory
.PHONY: copy-headers
copy-headers: $(BUILD_DIR)
	cp azuretls.h $(BUILD_DIR)/

# Test the library
.PHONY: test
test: $(TARGET) copy-headers
	cd examples && $(MAKE) test

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Install library to system paths (Unix-like systems)
.PHONY: install
install: $(TARGET) copy-headers
ifeq ($(GOOS),windows)
	@echo "Windows installation not implemented. Copy $(TARGET) to your desired location."
else
	sudo cp $(TARGET) /usr/local/lib/
	sudo cp azuretls.h /usr/local/include/
	sudo ldconfig 2>/dev/null || true
endif

# Uninstall library from system paths (Unix-like systems)
.PHONY: uninstall
uninstall:
ifeq ($(GOOS),windows)
	@echo "Windows uninstallation not implemented."
else
	sudo rm -f /usr/local/lib/lib$(LIB_NAME)*
	sudo rm -f /usr/local/include/azuretls.h
	sudo ldconfig 2>/dev/null || true
endif

# Show help
.PHONY: help
help:
	@echo "AzureTLS CFFI Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all                    Build for current platform"
	@echo "  build-all              Build for all platforms"
	@echo "  build-linux            Build for all Linux architectures"
	@echo "  build-windows          Build for all Windows architectures"
	@echo "  build-darwin           Build for all macOS architectures"
	@echo "  build-freebsd          Build for all FreeBSD architectures"
	@echo "  copy-headers           Copy header files to build directory"
	@echo "  test                   Run tests"
	@echo "  clean                  Remove build artifacts"
	@echo "  install                Install library system-wide (Unix-like)"
	@echo "  uninstall              Uninstall library (Unix-like)"
	@echo "  help                   Show this help"
	@echo ""
	@echo "Environment Variables:"
	@echo "  GOOS                   Target operating system"
	@echo "  GOARCH                 Target architecture"
	@echo "  CGO_ENABLED            Enable CGO (required)"
	@echo ""
	@echo "Current platform: $(GOOS)/$(GOARCH)"