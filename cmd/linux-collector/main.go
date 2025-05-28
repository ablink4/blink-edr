package main

import (
	"blink-edr/internal/collector/fsmon"
	"log"
	"os"
)

func main() {
	// some of the fsmon collectors require sudo rights
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (use sudo).")
	}

	log.Println("Starting Linux EDR filesystem monitor collector")

	if err := fsmon.StartFsMonitor("/"); err != nil {
		log.Fatalf("FsMon failed: %v", err)
	}
}
