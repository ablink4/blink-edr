package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	loader "blink-edr/internal/collector/ebpf/loader"
)

// Event represents the data emitted by the exec_logger eBPF program,
// its contents must match the struct in the C code exactly
type Event struct {
	PID  uint32
	Comm [16]byte
}

// StartExecMonitor loads the exec_logger eBPF program, attaches it,
// and prints the events to stdout.
func StartExecMonitor(ctx context.Context, objPath string) error {
	mod, err := loader.Load(objPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF module: %w", err)
	}
	defer mod.Close()

	prog, err := mod.Program("handle_execve")
	if err != nil {
		return fmt.Errorf("failed to find eBPF program: %w", err)
	}

	kprobe, err := link.Kprobe("sys_execve", prog, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe: %w", err)
	}
	defer kprobe.Close()

	eventsMap, err := mod.Map("events")
	if err != nil {
		return fmt.Errorf("failed to find perf event map: %w", err)
	}

	reader, err := perf.NewReader(eventsMap, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create perf reader: %w", err)
	}
	defer reader.Close()

	// handle ctrl+c as an exit path
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("exec_mon started.  Waiting for events...")

	go func() {
		<-sig
		fmt.Println("Received interrupt, stopping...")
		reader.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			record, err := reader.Read()
			if err != nil {
				/*
					if perf.IsClosed(err) {
						return nil
					}
				*/
				fmt.Errorf("error reading from perf buffer: %w", err)
				continue
			}

			var evt Event
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt)
			if err != nil {
				fmt.Errorf("failed to decode received event: %w", err)
				continue
			}

			fmt.Printf("[execve] PID: %d, Comm: %s\n", evt.PID, string(bytes.Trim(evt.Comm[:], "\x00")))
		}
	}
}

// "../../../build/exec_logger.bpf.o"
