BIN_DIR := bin
COLLECTOR_BIN := $(BIN_DIR)/blink-edr-collector

LINUX_COLLECTOR_DIR := ./cmd/linux-collector

PROTO_DIR := ./internal/proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

BPF_SRC := ebpf/programs/exec_logger.bpf.c
BPF_OBJ := build/exec_logger.bpf.o

KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)/build

GO_BUILD := go build

.PHONY: build clean proto bpf all

build: bpf linux-collector

linux-collector:
	@echo "Building linux collector"
	@$(GO_BUILD) -o $(COLLECTOR_BIN) $(LINUX_COLLECTOR_DIR)
	sudo setcap cap_sys_admin,cap_sys_ptrace+ep $(COLLECTOR_BIN)

# Compile the BPF C source file into a .o ELF using clang
bpf:
	@echo "Compiling eBPF programs..."
	@mkdir -p build
	@clang -O2 -g -Wall -target bpf \
		-I$(KERNEL_HEADERS)/include \
		-I$(KERNEL_HEADERS)/arch/$(shell uname -m)/include \
		-I$(KERNEL_HEADERS)/include/uapi \
		-I$(KERNEL_HEADERS)/arch/$(shell uname -m)/include/uapi \
		-c $(BPF_SRC) -o $(BPF_OBJ)

proto:
	@echo "Generating protobuf Go code..."
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)

all: proto bpf build

clean:
	@echo "Cleaning up binaries"
	@rm -rf $(BIN_DIR) build
	@find $(PROTO_DIR) -name "*.pb.go" -delete
