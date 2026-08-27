package config

import "testing"

func TestParseBytes(t *testing.T) {
	ok := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"1024", 1024},
		{"512MB", 512 * MB},
		{"512mb", 512 * MB},
		{"  512 MB  ", 512 * MB},
		{"1GB", GB},
		{"1GiB", GB}, // the explicit binary spelling means the same thing
		{"1.5GB", GB + GB/2},
		{"64K", 64 * KB},
		{"900B", 900},
	}
	for _, tc := range ok {
		got, err := ParseBytes(tc.in)
		if err != nil {
			t.Errorf("ParseBytes(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	bad := []string{"", "   ", "abc", "12x", "-5MB", "MB"}
	for _, in := range bad {
		if got, err := ParseBytes(in); err == nil {
			t.Errorf("ParseBytes(%q) = %d, want an error", in, got)
		}
	}
}
