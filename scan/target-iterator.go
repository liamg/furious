package scan

import (
	"fmt"
	"io"
	"net"
)

type TargetIterator struct {
	target string
	isCIDR bool
	index  int
	ip     net.IP
	ipnet  *net.IPNet
}

func NewTargetIterator(target string) *TargetIterator {

	ip, ipnet, err := net.ParseCIDR(target)

	ti := &TargetIterator{
		target: target,
		isCIDR: err == nil,
	}

	if ti.isCIDR {
		ti.ip = ip.Mask(ipnet.Mask)
		ti.ipnet = ipnet
	}

	return ti
}

func (ti *TargetIterator) Next() (net.IP, error) {

	ti.index++
	if !ti.isCIDR {
		if ti.index > 1 {
			return nil, io.EOF
		}

		if ip := net.ParseIP(ti.target); ip != nil {
			return ip, nil
		} else if ips, err := net.LookupIP(ti.target); err == nil {
			if len(ips) == 0 {
				return nil, fmt.Errorf("Lookup failed for '%s'", ti.target)
			}
			return ips[0], nil
		} else {
			return nil, err
		}
	}

	if ti.ipnet.Contains(ti.ip) {
		tIP := make([]byte, len(ti.ip))
		copy(tIP, ti.ip)
		ti.incrementIP()
		return tIP, nil
	}

	return nil, io.EOF
}

func (ti *TargetIterator) incrementIP() {
	for j := len(ti.ip) - 1; j >= 0; j-- {
		ti.ip[j]++
		if ti.ip[j] > 0 {
			break
		}
	}
}
