package probe

import (
	"runtime"
	"syscall"
	"unsafe"
)

// SIO_TCP_INFO is _WSAIORW(IOC_VENDOR, 39). The input DWORD selects the
// struct version: 0 is TCP_INFO_v0 (mstcpip.h, Windows 10 1703).
const sioTCPInfo = syscall.IOC_INOUT | syscall.IOC_VENDOR | 39

// tcpInfoV0 is TCP_INFO_v0. Field offsets are pinned by
// TestTCPInfoV0MatchesWindows: a missed pad would shift every counter and
// the trace would lie while still looking plausible.
type tcpInfoV0 struct {
	State             uint32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled uint8
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint8
}

func tcpInfoFromFd(fd uintptr) (TCPInfo, error) {
	ver := uint32(0)
	var raw tcpInfoV0
	var n uint32
	err := syscall.WSAIoctl(
		syscall.Handle(fd),
		sioTCPInfo,
		(*byte)(unsafe.Pointer(&ver)),
		uint32(unsafe.Sizeof(ver)),
		(*byte)(unsafe.Pointer(&raw)),
		uint32(unsafe.Sizeof(raw)),
		&n,
		nil,
		0,
	)
	runtime.KeepAlive(&ver)
	runtime.KeepAlive(&raw)
	if err != nil {
		return TCPInfo{}, err
	}
	return TCPInfo{
		RawBytes:        int(n),
		RttUs:           raw.RttUs,
		BytesInFlight:   raw.BytesInFlight,
		BytesRetrans:    raw.BytesRetrans,
		TimeoutEpisodes: raw.TimeoutEpisodes,
		BytesIn:         raw.BytesIn,
		BytesOut:        raw.BytesOut,
		SynRetrans:      raw.SynRetrans,
	}, nil
}
