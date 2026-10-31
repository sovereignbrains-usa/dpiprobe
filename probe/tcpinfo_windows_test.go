package probe

import (
	"testing"
	"unsafe"
)

func TestTCPInfoV0MatchesWindows(t *testing.T) {
	var s tcpInfoV0
	if unsafe.Sizeof(s) != 88 {
		t.Fatalf("sizeof TCP_INFO_v0 = %d, want 88", unsafe.Sizeof(s))
	}
	checks := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"State", unsafe.Offsetof(s.State), 0},
		{"Mss", unsafe.Offsetof(s.Mss), 4},
		{"ConnectionTimeMs", unsafe.Offsetof(s.ConnectionTimeMs), 8},
		{"TimestampsEnabled", unsafe.Offsetof(s.TimestampsEnabled), 16},
		{"RttUs", unsafe.Offsetof(s.RttUs), 20},
		{"BytesInFlight", unsafe.Offsetof(s.BytesInFlight), 28},
		{"BytesOut", unsafe.Offsetof(s.BytesOut), 48},
		{"BytesIn", unsafe.Offsetof(s.BytesIn), 56},
		{"BytesRetrans", unsafe.Offsetof(s.BytesRetrans), 68},
		{"TimeoutEpisodes", unsafe.Offsetof(s.TimeoutEpisodes), 80},
		{"SynRetrans", unsafe.Offsetof(s.SynRetrans), 84},
	}
	for _, c := range checks {
		if c.off != c.want {
			t.Errorf("%s at %d, want %d", c.name, c.off, c.want)
		}
	}
}

func TestSIOTCPInfoCode(t *testing.T) {
	if sioTCPInfo != 0xD8000027 {
		t.Fatalf("SIO_TCP_INFO = %#x, want 0xD8000027", sioTCPInfo)
	}
}
