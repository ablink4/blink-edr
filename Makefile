BIN_DIR := bin
COLLECTOR_BIN := $(BIN_DIR)/blink-edr-collector

LINUX_COLLECTOR_DIR := ./cmd/linux-collector

GO_BUILD := go build

.PHONY: build clean

build: linux-collector

linux-collector:
	@echo "Building linux collector"
	@$(GO_BUILD) -o $(COLLECTOR_BIN) $(LINUX_COLLECTOR_DIR)
	sudo setcap cap_sys_admin,cap_sys_ptrace+ep $(COLLECTOR_BIN)

all: build

clean:
	@echo "Cleaning up binaries"
	@rm -rf $(BIN_DIR)