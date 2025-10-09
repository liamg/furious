// +build linux

package scan

import (
	"net"

	"github.com/google/gopacket/routing"
)

type linuxRouter struct {
	router routing.Router
}

func newLinuxRouter() (Router, error) {
	router, err := routing.New()
	if err != nil {
		return nil, err
	}
	return &linuxRouter{router: router}, nil
}

func (r *linuxRouter) Route(dst net.IP) (iface *net.Interface, gateway net.IP, src net.IP, err error) {
	return r.router.Route(dst)
}