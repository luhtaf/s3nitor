package sysinfo

import (
	"runtime"
	"testing"
)

func TestParseVmHWM(t *testing.T) {
	const status = `Name:	s3scanner
VmPeak:	  1234567 kB
VmSize:	  1200000 kB
VmHWM:	    98765 kB
VmRSS:	    54321 kB
`
	got, err := parseVmHWM(status)
	if err != nil {
		t.Fatalf("parseVmHWM: %v", err)
	}
	// The kernel labels the field kB but reports kibibytes.
	if want := int64(98765 * 1024); got != want {
		t.Errorf("parseVmHWM = %d, want %d", got, want)
	}

	// VmHWM is the peak, not the current value: reading VmRSS by mistake would
	// silently under-report and produce limits that are too low.
	if got == 54321*1024 {
		t.Error("parseVmHWM returned VmRSS instead of the high-water mark")
	}

	if _, err := parseVmHWM("Name:\ts3scanner\n"); err == nil {
		t.Error("expected an error when VmHWM is absent")
	}
	if _, err := parseVmHWM("VmHWM:\tnotanumber kB\n"); err == nil {
		t.Error("expected an error on a malformed value")
	}
}

func TestParseCgroupPeak(t *testing.T) {
	got, err := parseCgroupPeak("536870912\n")
	if err != nil {
		t.Fatalf("parseCgroupPeak: %v", err)
	}
	if got != 536870912 {
		t.Errorf("parseCgroupPeak = %d, want 536870912", got)
	}
	if _, err := parseCgroupPeak("max\n"); err == nil {
		t.Error("expected an error on a non-numeric value")
	}
}

func TestMaxRSSUnitsDifferByPlatform(t *testing.T) {
	const raw = 1000
	got := maxRSSBytes(raw)
	if runtime.GOOS == "linux" {
		if got != raw*1024 {
			t.Errorf("on linux Maxrss is kibibytes: got %d, want %d", got, raw*1024)
		}
	} else if got != raw {
		t.Errorf("on %s Maxrss is bytes: got %d, want %d", runtime.GOOS, got, raw)
	}
}

// Whatever the platform, a running process has a non-zero peak and must name
// where the figure came from — an unlabelled number invites comparing a cgroup
// reading with a getrusage one.
func TestPeakRSSReportsSomethingLabelled(t *testing.T) {
	bytes, source, err := PeakRSS()
	if err != nil {
		t.Fatalf("PeakRSS: %v", err)
	}
	if bytes <= 0 {
		t.Errorf("PeakRSS = %d bytes, want a positive value", bytes)
	}
	switch source {
	case "cgroup", "VmHWM", "getrusage":
	default:
		t.Errorf("unexpected source %q", source)
	}
}
