package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ProcessInfo struct {
	PID     int
	ExePath string
	Cmdline string
}

type ProcPoller struct {
	seen map[int]struct{}
}

func NewProcPoller() *ProcPoller {
	return &ProcPoller{
		seen: make(map[int]struct{}),
	}
}

// Poll reads /proc and returns any new processes not seen before
func (p *ProcPoller) Poll() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}

	var newProcs []ProcessInfo

	for _, entry := range entries {
		// only want PID data entries for now, all of which are in directories
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			// PID entries have directories named with the PID, all others we want to ignore
			continue
		}

		// ignore items that we've seen before
		if _, alreadySeen := p.seen[pid]; alreadySeen {
			continue
		}

		procInfo, err := getProcessInfo(pid)
		if err != nil {
			continue // process probably exited
		}

		p.seen[pid] = struct{}{}
		newProcs = append(newProcs, procInfo)
	}

	return newProcs, nil
}

// getProcessInfo gets data for an individual process
func getProcessInfo(pid int) (ProcessInfo, error) {
	// assumes you already sanity checked that /proc/pid exists (TODO: check here)
	base := fmt.Sprintf("/proc/%d", pid)

	exePath, err := os.Readlink(filepath.Join(base, "exe"))
	if err != nil {
		return ProcessInfo{}, err
	}

	cmdBytes, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return ProcessInfo{}, err
	}

	cmdline := strings.ReplaceAll(string(cmdBytes), "\x00", " ")

	return ProcessInfo{
		PID:     pid,
		ExePath: exePath,
		Cmdline: strings.TrimSpace(cmdline),
	}, nil
}
