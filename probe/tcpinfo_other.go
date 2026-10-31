//go:build !windows && !linux

package probe

import "errors"

func tcpInfoFromFd(uintptr) (TCPInfo, error) {
	// macOS would be TCP_CONNECTION_INFO. Until that lands, callers keep
	// the plain timeout.
	return TCPInfo{}, errors.New("эта ОС не отдаёт сведения TCP")
}
