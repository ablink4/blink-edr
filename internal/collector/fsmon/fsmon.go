package fsmon

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// StartFsMonitor uses fanotify to monitor filesystem events
func StartFsMonitor(mountPath string) error {
	fanFD, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("fanotify init: %w", err)
	}

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

			// parse path from file descriptor
			path := fmt.Sprintf("/proc/self/fd/%d", event.Fd)
			eventPath, _ := os.Readlink(path)

			var ignorePaths = map[string]struct{}{
				"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": {}, // dynamic linker/loader process called every time a program is loaded
				"/usr/lib/x86_64-linux-gnu/libc.so.6":            {},
			}

			// this is the dynamic linker/loader that is called every time a program is executed, and it is just noise
			if _, skip := ignorePaths[eventPath]; !skip {
				if event.Mask&unix.FAN_OPEN_EXEC != 0 {
					log.Printf("EXEC: PID=%d FILE=%s\n", event.Pid, eventPath)
				} else if event.Mask&unix.FAN_ACCESS != 0 {
					log.Printf("ACCESS: PID=%d FILE=%s\n", event.Pid, eventPath)
				} else if event.Mask&unix.FAN_MODIFY != 0 {
					log.Printf("MODIFY: PID=%d FILE=%s\n", event.Pid, eventPath)
				}
			}

			unix.Close(int(event.Fd))
			offset += int(event.Event_len)
		}
	}
}
