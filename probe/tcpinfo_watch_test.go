package probe

import (
	"strings"
	"testing"
	"time"
)

func TestInterpretTCP(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	drop := []tcpSample{
		{At: ms(0), TCPInfo: TCPInfo{BytesOut: 517, BytesInFlight: 517}},
		{At: ms(1000), TCPInfo: TCPInfo{BytesOut: 517, BytesInFlight: 517, BytesRetrans: 517, TimeoutEpisodes: 1}},
		{At: ms(8000), TCPInfo: TCPInfo{BytesOut: 1200, BytesInFlight: 400, BytesRetrans: 2000, TimeoutEpisodes: 3}},
	}
	if got := interpretHello(TCPInfo{}, drop); !strings.Contains(got, "не подтверждены") || strings.Contains(got, "ответа нет") {
		t.Fatalf("drop: %s", got)
	}

	acked := []tcpSample{
		{At: ms(0), TCPInfo: TCPInfo{BytesOut: 517, BytesInFlight: 517}},
		{At: ms(40), TCPInfo: TCPInfo{BytesOut: 517, BytesInFlight: 0}},
		{At: ms(8000), TCPInfo: TCPInfo{BytesOut: 517, BytesInFlight: 0}},
	}
	if got := interpretHello(TCPInfo{}, acked); !strings.Contains(got, "подтверждены, ответа нет") {
		t.Fatalf("acked silence: %s", got)
	}

	alive := []tcpSample{
		{At: ms(0), TCPInfo: TCPInfo{BytesOut: 517, BytesInFlight: 517}},
		{At: ms(30), TCPInfo: TCPInfo{BytesOut: 517, BytesInFlight: 0, BytesIn: 4200}},
	}
	if got := interpretHello(TCPInfo{}, alive); !strings.Contains(got, "ответ пришёл") {
		t.Fatalf("alive: %s", got)
	}

	// ACK landed before the first sample. Still an answer.
	fast := []tcpSample{
		{At: ms(0), TCPInfo: TCPInfo{BytesOut: 1588, BytesIn: 3391}},
		{At: ms(8000), TCPInfo: TCPInfo{BytesOut: 1588, BytesIn: 3391}},
	}
	if got := interpretHello(TCPInfo{}, fast); !strings.Contains(got, "ответ пришёл") {
		t.Fatalf("fast: %s", got)
	}

	// Certificate already counted in base. A later response must not hide
	// padding that the kernel is still retransmitting.
	base := TCPInfo{BytesIn: 5000, BytesOut: 1500}
	fat := []tcpSample{
		{At: ms(50), TCPInfo: TCPInfo{BytesIn: 5600, BytesOut: 2500, BytesInFlight: 0}},
		{At: ms(400), TCPInfo: TCPInfo{BytesIn: 5600, BytesOut: 20000, BytesInFlight: 8000, BytesRetrans: 8000, TimeoutEpisodes: 1}},
		{At: ms(8000), TCPInfo: TCPInfo{BytesIn: 5600, BytesOut: 28000, BytesInFlight: 8000, BytesRetrans: 24000, TimeoutEpisodes: 4}},
	}
	if got := interpretFat(base, fat); !strings.Contains(got, "не подтверждены") {
		t.Fatalf("fat drop: %s", got)
	}
}
