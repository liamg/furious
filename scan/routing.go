package scan

import (
	"fmt"
	"net"
	"runtime"
)

// Router provides cross-platform network routing functionality
type Router interface {
	Route(dst net.IP) (iface *net.Interface, gateway net.IP, src net.IP, err error)
}

// NewRouter creates a new cross-platform router
func NewRouter() (Router, error) {
	switch runtime.GOOS {
	case "darwin":
		return newDarwinRouter()
	case "linux":
		return newLinuxRouter()
	default:
		// For unsupported platforms, return an error
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}