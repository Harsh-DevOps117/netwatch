BINARY_NAME=detector
BUILD_DIR=bin
GO=go

.PHONY: all build clean test coverage vet fmt tidy run run-live sample attack demo help

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) main.go

clean:
	rm -rf $(BUILD_DIR) *.pcap alerts.json coverage.out

test:
	$(GO) test -v ./...

coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

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

sample: build
	./$(BUILD_DIR)/$(BINARY_NAME) generate sample
	./$(BUILD_DIR)/$(BINARY_NAME) analyze sample.pcap

attack: build
	./$(BUILD_DIR)/$(BINARY_NAME) generate attack
	./$(BUILD_DIR)/$(BINARY_NAME) analyze attack_sample.pcap

demo: sample attack

help:
	@echo "Available targets:"
	@echo "  build      Build binary in $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "  test       Run unit tests"
	@echo "  coverage   Run unit tests with coverage report"
	@echo "  vet        Run go vet"
	@echo "  fmt        Format Go files"
	@echo "  tidy       Run go mod tidy"
	@echo "  run        Build and run detector CLI"
	@echo "  run-live   Run live network monitor"
	@echo "  sample     Generate baseline PCAP and analyze"
	@echo "  attack     Generate attack PCAP and analyze"
	@echo "  demo       Run sample and attack demos"
	@echo "  clean      Remove build artifacts and generated test files"
