package fsmon

import (
	fsmon "blink-edr/internal/proto"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type FsMonData struct {
	ComputerId               string
	EventType                string
	Name                     string
	Pid                      int
	File                     string
	Cmd                      string
	ProcessName              string
	Path                     string
	Ppid                     int
	Uid                      int
	Gid                      int
	Groups                   []int32
	CapEff                   string
	CapPrm                   string
	CapBnd                   string
	Seccomp                  int
	NoNewPrivs               int
	Threads                  int
	VmSize                   int
	VmRss                    int
	VmData                   int
	VoluntaryCtxtSwitches    int
	NonVoluntaryCtxtSwitches int
}

// gRPC connection details for blink-yadp
const (
	serverAddr = "192.168.24.128:50051"
	batchSize  = 1000
)

// StartFsMonitor uses fanotify to monitor filesystem events
func StartFsMonitor(mountPath string) error {
	fanFD, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("fanotify init: %w", err)
	}
	defer unix.Close(fanFD) // ensure fd gets closed

	// mark the mount point to monitor
	err = unix.FanotifyMark(fanFD,
		unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
		unix.FAN_OPEN_EXEC|unix.FAN_ACCESS|unix.FAN_MODIFY|unix.FAN_EVENT_ON_CHILD,
		unix.AT_FDCWD,
		mountPath,
	)
	if err != nil {
		return fmt.Errorf("fanotify mark: %w", err)
	}

	log.Println("Filesystem fanotify monitor started on:", mountPath)

	var ignorePaths = map[string]struct{}{
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": {}, // dynamic linker/loader process called every time a program is loaded
		"/usr/lib/x86_64-linux-gnu/libc.so.6":            {},
	}

	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to dial gRPC: %v", err)
	}
	defer conn.Close()

	client := fsmon.NewFsMonIngestorClient(conn)
	ctx := context.Background()

	stream, err := client.SendFsMonStream(ctx)
	if err != nil {
		log.Fatalf("failed to open stream: %v", err)
	}

	computerId, err := getProductUUID()
	if err != nil {
		fmt.Errorf("Error reading product ID: %v", err)
	}

	var batch fsmon.FsMonBatch
	eventCounter := 0 // to track how many events are added to a batch
	var buf [4096]byte

	for {
		n, err := unix.Read(fanFD, buf[:])
		if err != nil {
			return fmt.Errorf("fanotify read: %w", err)
		}

		offset := 0
		for offset < n {
			event := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if event.Vers != unix.FANOTIFY_METADATA_VERSION {
				return fmt.Errorf("fanotify version mismatch")
			}

			procInfo, err := NewFsMonDataFromEvent(event, ignorePaths)
			if err != nil {
				log.Printf("Error handling event: %v", err)
			} else if procInfo != nil {
				msg := &fsmon.FsMon{
					Timestamp:               timestamppb.Now(),
					EventType:               procInfo.EventType,
					Name:                    procInfo.Name,
					Pid:                     int32(procInfo.Pid),
					File:                    procInfo.File,
					Cmd:                     procInfo.Cmd,
					ProcName:                procInfo.ProcessName,
					Path:                    procInfo.Path,
					Ppid:                    int32(procInfo.Ppid),
					Uid:                     int32(procInfo.Uid),
					Gid:                     int32(procInfo.Gid),
					Groups:                  procInfo.Groups,
					CapEff:                  procInfo.CapEff,
					CapPrm:                  procInfo.CapPrm,
					CapBnd:                  procInfo.CapBnd,
					Seccomp:                 int32(procInfo.Seccomp),
					NoNewPrivs:              int32(procInfo.NoNewPrivs),
					Threads:                 int32(procInfo.Threads),
					VmSize:                  int32(procInfo.VmSize),
					VmRss:                   int32(procInfo.VmRss),
					VmData:                  int32(procInfo.VmData),
					VoluntaryCtxSwitches:    int64(procInfo.VoluntaryCtxtSwitches),
					NonvoluntaryCtxSwitches: int64(procInfo.NonVoluntaryCtxtSwitches),
					ComputerId:              computerId,
				}

				batch.Items = append(batch.Items, msg)
				eventCounter += 1

				if eventCounter >= batchSize {
					if err := stream.Send(&batch); err != nil {
						log.Printf("stream send error: %v", err)
					}

					batch.Reset()
				}
			}

			unix.Close(int(event.Fd))
			offset += int(event.Event_len)
		}
	}
}

// NewFsMonDataFromEvent creates a complete FsMonData from a fanotify event
func NewFsMonDataFromEvent(event *unix.FanotifyEventMetadata, ignorePaths map[string]struct{}) (*FsMonData, error) {
	fdPath := fmt.Sprintf("/proc/self/fd/%d", event.Fd)
	eventPath, err := os.Readlink(fdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve fd path: %w", err)
	}

	// skip ignored paths
	if _, skip := ignorePaths[eventPath]; skip {
		return nil, nil
	}

	// read auxiliary data
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", event.Pid))
	exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", event.Pid))

	// parse status
	info, err := parseProcStatus(int(event.Pid))
	if err != nil {
		return nil, fmt.Errorf("parseProcStatus: %w", err)
	}

	// fill remaining fields
	info.Cmd = strings.ReplaceAll(string(cmdline), "\x00", " ")
	info.File = eventPath
	info.Path = exePath

	switch {
	case event.Mask&unix.FAN_OPEN_EXEC != 0:
		info.EventType = "EXEC"
	case event.Mask&unix.FAN_ACCESS != 0:
		info.EventType = "ACCESS"
	case event.Mask&unix.FAN_MODIFY != 0:
		info.EventType = "MODIFY"
	default:
		info.EventType = "UNKNOWN"
	}

	return info, nil
}

// parseProcStatus processes the data from /proc/pid/status
func parseProcStatus(pid int) (*FsMonData, error) {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return nil, fmt.Errorf("reading status: %w", err)
	}

	info := &FsMonData{Pid: pid}
	lines := strings.SplitSeq(string(data), "\n")

	for line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Name:"):
			info.ProcessName = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			info.Ppid = parseIntField(line)
		case strings.HasPrefix(line, "Uid:"):
			info.Uid = parseIntField(line)
		case strings.HasPrefix(line, "Gid:"):
			info.Gid = parseIntField(line)
		case strings.HasPrefix(line, "Groups:"):
			info.Groups = parseIntList(strings.TrimPrefix(line, "Groups:"))
		case strings.HasPrefix(line, "CapEff:"):
			info.CapEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		case strings.HasPrefix(line, "CapPrm:"):
			info.CapPrm = strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
		case strings.HasPrefix(line, "CapBnd:"):
			info.CapBnd = strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
		case strings.HasPrefix(line, "Seccomp:"):
			info.Seccomp = parseIntField(line)
		case strings.HasPrefix(line, "NoNewPrivs:"):
			info.NoNewPrivs = parseIntField(line)
		case strings.HasPrefix(line, "Threads:"):
			info.Threads = parseIntField(line)
		case strings.HasPrefix(line, "VmSize:"):
			info.VmSize = parseIntField(line)
		case strings.HasPrefix(line, "VmRSS:"):
			info.VmRss = parseIntField(line)
		case strings.HasPrefix(line, "VmData:"):
			info.VmData = parseIntField(line)
		case strings.HasPrefix(line, "voluntary_ctxt_switches:"):
			info.VoluntaryCtxtSwitches = parseIntField(line)
		case strings.HasPrefix(line, "nonvoluntary_ctxt_switches:"):
			info.NonVoluntaryCtxtSwitches = parseIntField(line)
		}
	}

	return info, nil
}

// parseIntField extracts an int value
func parseIntField(line string) int {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}

	n, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}

	return n
}

// parseIntList parses a list of space-separated ints like the Groups field in /proc/pid/status
func parseIntList(s string) []int32 {
	fields := strings.Fields(s)
	result := make([]int32, 0, len(fields))

	for _, f := range fields {
		if x, err := strconv.Atoi(f); err == nil {
			result = append(result, int32(x))
		}
	}

	return result
}

// getProductUUID reads the machine's BIOS UUID as a unique identifier for the machine, if not run as root this will be blank
func getProductUUID() (string, error) {
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}
