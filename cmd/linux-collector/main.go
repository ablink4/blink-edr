package main

import (
	exec_mon "blink-edr/internal/collector/ebpf"
	"context"
	"log"
	"os"
)

func main() {
	// some of the fsmon collectors require sudo rights
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (use sudo).")
	}

	log.Println("Starting Linux EDR collector")

	ctx := context.Background()

	// TODO: this path needs to be made more robust and not dependent on where you run the program from nor having an absolute path
	err := exec_mon.StartExecMonitor(ctx, "./build/exec_logger.bpf.o")
	if err != nil {
		log.Fatalf("monitor failed: %v", err)
	}
}
