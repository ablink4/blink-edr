package main

import (
	"blink-edr/internal/collector/proc"
	"log"
	"time"
)

func main() {
	log.Println("Starting Linux EDR collector (polling mode)")

	poller := proc.NewProcPoller()

	for {
		newProcs, err := poller.Poll()
		if err != nil {
			log.Printf("Error polling /proc: %v\n", err)
			continue
		}

		for _, proc := range newProcs {
			log.Printf("New process detected: PID=%d, EXE=%s, CMD=%s\n",
				proc.PID, proc.ExePath, proc.Cmdline)
		}

		time.Sleep(2 * time.Second)
	}
}
