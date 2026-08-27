// Package sysinfo reports how much memory the process actually used.
//
// The number this package returns is the one Kubernetes looks at when it
// decides whether to kill the pod, which is why it is not read from
// runtime.MemStats. MemStats describes the Go heap; the SQLite driver is cgo and
// allocates outside it, as do the OS-level buffers behind every transfer. A
// process can therefore look healthy in MemStats and still be OOM-killed, and
// sizing a deployment from those numbers produces limits that are too low in a
// way that only shows up in production.
//
// What matters for sizing is the high-water mark, not the current value: a
// sample taken at exit misses the peak that happened halfway through.
package sysinfo

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// PeakRSS returns the highest resident set size the process reached, together
// with where the figure came from.
//
// The source is returned rather than hidden because the readings are not
// equivalent: a cgroup peak covers the whole container, VmHWM covers this
// process only, and getrusage on macOS is a development convenience that says
// nothing about how the container will behave.
func PeakRSS() (bytes int64, source string, err error) {
	// Preferred: cgroup v2 exposes the container's own high-water mark, which is
	// exactly what the OOM killer compares against limits.memory.
	if b, err := readCgroupPeak(); err == nil {
		return b, "cgroup", nil
	}

	// Linux without cgroup v2, or outside a container.
	if b, err := readVmHWM(); err == nil {
		return b, "VmHWM", nil
	}

	// macOS and friends: useful while developing, not a container figure.
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, "", fmt.Errorf("no peak memory source available: %w", err)
	}
	return maxRSSBytes(ru.Maxrss), "getrusage", nil
}

// cgroupPeakFiles are tried in order: memory.peak is the v2 high-water mark
// (kernel 5.19+), max_usage_in_bytes is its v1 equivalent.
var cgroupPeakFiles = []string{
	"/sys/fs/cgroup/memory.peak",
	"/sys/fs/cgroup/memory/memory.max_usage_in_bytes",
}

func readCgroupPeak() (int64, error) {
	for _, path := range cgroupPeakFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := parseCgroupPeak(string(raw))
		if err != nil {
			continue
		}
		return v, nil
	}
	return 0, fmt.Errorf("no readable cgroup peak file")
}

func parseCgroupPeak(raw string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
}

func readVmHWM() (int64, error) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	return parseVmHWM(string(raw))
}

// parseVmHWM pulls the peak resident size out of /proc/self/status.
//
// The field is reported in kibibytes despite the "kB" label, which is a
// long-standing kernel quirk rather than a typo here.
func parseVmHWM(status string) (int64, error) {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed VmHWM line: %q", line)
		}
		kib, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("malformed VmHWM value: %q", fields[1])
		}
		return kib * 1024, nil
	}
	return 0, fmt.Errorf("VmHWM not present")
}

// maxRSSBytes normalises rusage.Maxrss, whose unit differs by platform: Linux
// reports kibibytes, macOS and the BSDs report bytes.
func maxRSSBytes(maxrss int64) int64 {
	if runtime.GOOS == "linux" {
		return maxrss * 1024
	}
	return maxrss
}
