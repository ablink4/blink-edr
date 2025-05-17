package main

import (
	"blink-edr/internal/collector/fsmon"
	"log"
)

func main() {
	log.Println("Starting Linux EDR filesystem monitor collector")

	if err := fsmon.StartFsMonitor("/"); err != nil {
		log.Fatalf("FsMon failed: %v", err)
	}
}
