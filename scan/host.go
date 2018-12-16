package scan

import (
	"net"
	"time"
)

type Host struct {
	IP net.IP
}

type PortState uint8

const (
	PortUnknown PortState = iota
	PortOpen
	PortClosed
	PortFiltered
)

func (h *Host) ScanConnect(port int, timeout time.Duration) (PortState, error) {
	conn, err := net.DialTimeout("tcp", h.IP.String(), timeout)
	if err != nil {
		return PortClosed, nil
	}
	defer conn.Close()
	return PortOpen, nil
}
