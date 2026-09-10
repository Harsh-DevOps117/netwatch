BINARY_NAME=detector
BUILD_DIR=bin
GO=go

.PHONY: all build clean vet fmt tidy run run-live help

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) main.go

clean:
	rm -rf $(BUILD_DIR) *.pcap alerts.json

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

run-live: build
	./$(BUILD_DIR)/$(BINARY_NAME) --live

help:
	@echo "Available targets:"
	@echo "  build      Build binary in $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "  vet        Run go vet"
	@echo "  fmt        Format Go files"
	@echo "  tidy       Run go mod tidy"
	@echo "  run        Build and run detector CLI"
	@echo "  run-live   Run live network monitor"
	@echo "  clean      Remove build artifacts"
