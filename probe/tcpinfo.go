package probe

import (
	"errors"
	"net"
)

// TCPInfo is one look at what the kernel already knows about a TCP
// connection. Reading it sends nothing: the fields are counters the stack
// keeps for its own retransmits.
//
// Available is false when this OS has no such call. Callers then keep the
// old timeout instead of guessing.
type TCPInfo struct {
	Available bool
	// RawBytes is how many bytes the kernel wrote into its struct. A
	// mismatch with the layout we compiled means the fields are not
	// trustworthy.
	RawBytes        int
	RttUs           uint32
	BytesInFlight   uint32
	BytesRetrans    uint32
	TimeoutEpisodes uint32
	BytesIn         uint64
	BytesOut        uint64
	SynRetrans      uint8
}

// ReadTCPInfo snapshots c. The connection must be a TCP socket this
// process dialed; a TLS conn has to be unwrapped by the caller first.
func ReadTCPInfo(c *net.TCPConn) (TCPInfo, error) {
	if c == nil {
		return TCPInfo{}, errors.New("tcp info: нет соединения")
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return TCPInfo{}, err
	}
	var info TCPInfo
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		info, sockErr = tcpInfoFromFd(fd)
	})
	if err != nil {
		return TCPInfo{}, err
	}
	if sockErr != nil {
		return TCPInfo{}, sockErr
	}
	info.Available = true
	return info, nil
}
