BIN_DIR := bin
COLLECTOR_BIN := $(BIN_DIR)/blink-edr-collector

LINUX_COLLECTOR_DIR := ./cmd/linux-collector

PROTO_DIR := ./internal/proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

GO_BUILD := go build

.PHONY: build clean

build: linux-collector

linux-collector:
	@echo "Building linux collector"
	@$(GO_BUILD) -o $(COLLECTOR_BIN) $(LINUX_COLLECTOR_DIR)
	sudo setcap cap_sys_admin,cap_sys_ptrace+ep $(COLLECTOR_BIN)

proto:
	@echo "Generating protobuf Go code..."
	@protoc --go_out=. --go_opt=paths=source_relative \
			--go-grpc_out=. --go-grpc_opt=paths=source_relative \
			$(PROTO_FILES)

all: proto build

clean:
	@echo "Cleaning up binaries"
	@rm -rf $(BIN_DIR)
	@find $(PROTO_DIR) -name "*.pb.go" -delete