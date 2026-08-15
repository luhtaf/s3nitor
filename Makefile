# Variables
BINARY_NAME=s3scanner
BUILD_DIR=build
DOCKER_IMAGE=s3scanner

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(shell git describe --tags --always --dirty)"

.PHONY: all build clean test deps docker-build docker-run help

# Default target
all: clean build

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/s3scanner

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run

# Install dependencies
install:
	@echo "Installing dependencies..."
	$(GOGET) -v -t -d ./...

# Run the application
run:
	@echo "Running $(BINARY_NAME)..."
	$(GOCMD) run ./cmd/s3scanner/main.go

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker run --env-file .env $(DOCKER_IMAGE)

# Build a release binary for the HOST platform only.
#
# Do NOT cross-compile this project with plain `GOOS=... go build`: Go silently
# sets CGO_ENABLED=0 when the target differs from the host, and mattn/go-sqlite3
# then compiles to a stub that panics at startup with
#   "Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work".
# The build succeeds, the binary is broken. Multi-platform artifacts are built
# natively per-OS by .github/workflows/release.yml — push a v* tag instead.
release: clean
	@echo "Creating release build for host platform ($(shell go env GOOS)/$(shell go env GOARCH))..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-$(shell go env GOOS)-$(shell go env GOARCH) ./cmd/s3scanner

# Show help
help:
	@echo "Available targets:"
	@echo "  build         - Build the application"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  deps          - Download dependencies"
	@echo "  fmt           - Format code"
	@echo "  lint          - Lint code"
	@echo "  install       - Install dependencies"
	@echo "  run           - Run the application"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  release       - Create release builds"
	@echo "  help          - Show this help"
