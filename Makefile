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

# Create release build
release: clean
	@echo "Creating release build..."
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/s3scanner
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/s3scanner
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/s3scanner

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
