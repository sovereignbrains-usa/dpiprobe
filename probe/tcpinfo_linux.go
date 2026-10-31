package probe

import (
	"syscall"
	"unsafe"
)

// TCP_INFO, from linux/tcp.h. Not exported by the standard syscall package.
const tcpInfoOpt = 11

// tcpInfoLinux is the prefix of struct tcp_info. The kernel may write a
// shorter or longer struct; fields past the returned size stay zero and
// are not read.
type tcpInfoLinux struct {
	State       uint8
	CaState     uint8
	Retransmits uint8
	Probes      uint8
	Backoff     uint8
	Options     uint8
	Scales      uint8
	RateFlags   uint8

	Rto     uint32
	Ato     uint32
	SndMss  uint32
	RcvMss  uint32
	Unacked uint32
	Sacked  uint32
	Lost    uint32
	Retrans uint32
	Fackets uint32

	LastDataSent uint32
	LastAckRecv  uint32
	LastDataRecv uint32
	LastAckSent  uint32

	Pmtu        uint32
	RcvSsthresh uint32
	Rtt         uint32
	Rttvar      uint32
	SndSsthresh uint32
	SndCwnd     uint32
	Advmss      uint32
	Reordering  uint32

	RcvRtt   uint32
	RcvSpace uint32

	TotalRetrans uint32

	PacingRate    uint64
	MaxPacingRate uint64
	BytesAcked    uint64
	BytesReceived uint64
	SegsOut       uint32
	SegsIn        uint32
	NotSentBytes  uint32
	MinRtt        uint32
	DataSegsIn    uint32
	DataSegsOut   uint32

	DeliveryRate  uint64
	BusyTime      uint64
	RwndLimited   uint64
	SndbufLimited uint64

	Delivered   uint32
	DeliveredCe uint32

	BytesSent    uint64
	BytesRetrans uint64
	DsackDups    uint32
	ReordSeen    uint32
	RcvOoopack   uint32
	SndWnd       uint32
}

func tcpInfoFromFd(fd uintptr) (TCPInfo, error) {
	var raw tcpInfoLinux
	size := uint32(unsafe.Sizeof(raw))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		uintptr(syscall.IPPROTO_TCP),
		uintptr(tcpInfoOpt),
		uintptr(unsafe.Pointer(&raw)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return TCPInfo{}, errno
	}
	info := TCPInfo{RawBytes: int(size), RttUs: raw.Rtt}
	// tcpi_retransmits counts the current timeout backoff. It is the
	// closest Linux has to Windows TimeoutEpisodes.
	info.TimeoutEpisodes = uint32(raw.Retransmits)
	if int(size) >= int(unsafe.Offsetof(raw.TotalRetrans))+4 && raw.SndMss > 0 && info.BytesRetrans == 0 {
		info.BytesRetrans = raw.TotalRetrans * raw.SndMss
	}
	if int(size) >= int(unsafe.Offsetof(raw.BytesReceived))+8 {
		info.BytesIn = raw.BytesReceived
	}
	if int(size) >= int(unsafe.Offsetof(raw.BytesRetrans))+8 {
		info.BytesRetrans = uint32(clampU64(raw.BytesRetrans))
	}
	sentOff := unsafe.Offsetof(raw.BytesSent)
	ackedOff := unsafe.Offsetof(raw.BytesAcked)
	if int(size) >= int(sentOff)+8 && int(size) >= int(ackedOff)+8 && raw.BytesSent >= raw.BytesAcked {
		info.BytesOut = raw.BytesSent
		info.BytesInFlight = uint32(clampU64(raw.BytesSent - raw.BytesAcked))
	} else if raw.SndMss > 0 {
		info.BytesInFlight = raw.Unacked * raw.SndMss
	}
	return info, nil
}

func clampU64(n uint64) uint64 {
	if n > uint64(^uint32(0)) {
		return uint64(^uint32(0))
	}
	return n
}
