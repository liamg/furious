package scan

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// RouteInfo contains routing information for a destination
type RouteInfo struct {
	Interface *net.Interface
	Gateway   net.IP
	SrcIP     net.IP
}

// GetRoute returns routing information for the given destination IP
func GetRoute(dst net.IP) (*RouteInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return getRouteLinux(dst)
	case "darwin":
		return getRouteDarwin(dst)
	case "windows":
		return getRouteWindows(dst)
	default:
		return nil, fmt.Errorf("routing not supported on %s", runtime.GOOS)
	}
}

// getRouteLinux gets routing info on Linux using ip route command
func getRouteLinux(dst net.IP) (*RouteInfo, error) {
	cmd := exec.Command("ip", "route", "get", dst.String())
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get route: %v", err)
	}

	return parseLinuxRoute(string(output))
}

// getRouteDarwin gets routing info on macOS using route command
func getRouteDarwin(dst net.IP) (*RouteInfo, error) {
	cmd := exec.Command("route", "-n", "get", dst.String())
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get route: %v", err)
	}

	return parseDarwinRoute(string(output))
}

// getRouteWindows gets routing info on Windows using route command
func getRouteWindows(dst net.IP) (*RouteInfo, error) {
	// Fall back to default interface for Windows
	iface, err := GetDefaultInterface()
	if err != nil {
		return nil, err
	}
	
	// Get source IP from interface
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("could not get interface addresses: %v", err)
	}
	
	var srcIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				srcIP = ipnet.IP
				break
			}
		}
	}
	
	if srcIP == nil {
		return nil, fmt.Errorf("could not determine source IP")
	}
	
	return &RouteInfo{
		Interface: iface,
		Gateway:   nil, // Simplified for Windows
		SrcIP:     srcIP,
	}, nil
}

// parseLinuxRoute parses Linux 'ip route get' output
func parseLinuxRoute(output string) (*RouteInfo, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("no route output")
	}

	fields := strings.Fields(lines[0])
	var gateway net.IP
	var interfaceName string
	var srcIP net.IP

	for i, field := range fields {
		switch field {
		case "via":
			if i+1 < len(fields) {
				gateway = net.ParseIP(fields[i+1])
			}
		case "dev":
			if i+1 < len(fields) {
				interfaceName = fields[i+1]
			}
		case "src":
			if i+1 < len(fields) {
				srcIP = net.ParseIP(fields[i+1])
			}
		}
	}

	if interfaceName == "" {
		return nil, fmt.Errorf("could not determine interface")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("could not get interface %s: %v", interfaceName, err)
	}

	if srcIP == nil {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("could not get interface addresses: %v", err)
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					srcIP = ipnet.IP
					break
				}
			}
		}
	}

	return &RouteInfo{
		Interface: iface,
		Gateway:   gateway,
		SrcIP:     srcIP,
	}, nil
}

// parseDarwinRoute parses macOS 'route -n get' output
func parseDarwinRoute(output string) (*RouteInfo, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var gateway net.IP
	var interfaceName string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				gateway = net.ParseIP(parts[1])
			}
		} else if strings.HasPrefix(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				interfaceName = parts[1]
			}
		}
	}

	if interfaceName == "" {
		return nil, fmt.Errorf("could not determine interface")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("could not get interface %s: %v", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("could not get interface addresses: %v", err)
	}
	
	var srcIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				srcIP = ipnet.IP
				break
			}
		}
	}

	if srcIP == nil {
		return nil, fmt.Errorf("could not determine source IP")
	}

	return &RouteInfo{
		Interface: iface,
		Gateway:   gateway,
		SrcIP:     srcIP,
	}, nil
}

// GetDefaultInterface returns the default network interface
func GetDefaultInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return &iface, nil
			}
		}
	}
	
	return nil, fmt.Errorf("no suitable network interface found")
}