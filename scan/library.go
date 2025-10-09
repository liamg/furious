package scan

import (
	"context"
	"time"
)

// LibraryConfig provides a simple configuration for library usage
type LibraryConfig struct {
	TimeoutMS   int    // Timeout in milliseconds (default: 2000)
	Workers     int    // Number of parallel workers (default: 500)
	ScanType    string // "syn", "connect", or "device" (default: "connect")
	Retries     int    // Number of retries (default: 1)
}

// DefaultLibraryConfig returns a sensible default configuration for library usage
func DefaultLibraryConfig() LibraryConfig {
	return LibraryConfig{
		TimeoutMS: 2000,
		Workers:   500,
		ScanType:  "connect", // Connect scan doesn't require root
		Retries:   1,
	}
}

// NewScannerFromConfig creates a scanner from a configuration
func NewScannerFromConfig(target string, config LibraryConfig) (Scanner, error) {
	ti := NewTargetIterator(target)
	timeout := time.Duration(config.TimeoutMS) * time.Millisecond
	
	switch config.ScanType {
	case "syn", "stealth":
		return NewSynScanner(ti, timeout, config.Workers), nil
	case "connect":
		return NewConnectScanner(ti, timeout, config.Workers), nil
	case "device":
		return NewDeviceScanner(ti, timeout), nil
	default:
		return NewConnectScanner(ti, timeout, config.Workers), nil
	}
}

// SimpleConnectScan performs a simple connect scan with sensible defaults
func SimpleConnectScan(target string, ports []int) ([]Result, error) {
	return SimpleConnectScanWithTimeout(target, ports, 2000)
}

// SimpleConnectScanWithTimeout performs a connect scan with specified timeout in milliseconds
func SimpleConnectScanWithTimeout(target string, ports []int, timeoutMS int) ([]Result, error) {
	config := DefaultLibraryConfig()
	config.TimeoutMS = timeoutMS
	config.ScanType = "connect"
	
	scanner, err := NewScannerFromConfig(target, config)
	if err != nil {
		return nil, err
	}
	
	if err := scanner.Start(); err != nil {
		return nil, err
	}
	
	ctx := context.Background()
	return scanner.Scan(ctx, ports)
}

// SimpleSynScan performs a simple SYN scan with sensible defaults (requires root)
func SimpleSynScan(target string, ports []int) ([]Result, error) {
	return SimpleSynScanWithTimeout(target, ports, 2000)
}

// SimpleSynScanWithTimeout performs a SYN scan with specified timeout in milliseconds (requires root)
func SimpleSynScanWithTimeout(target string, ports []int, timeoutMS int) ([]Result, error) {
	config := DefaultLibraryConfig()
	config.TimeoutMS = timeoutMS
	config.ScanType = "syn"
	
	scanner, err := NewScannerFromConfig(target, config)
	if err != nil {
		return nil, err
	}
	
	if err := scanner.Start(); err != nil {
		return nil, err
	}
	
	ctx := context.Background()
	return scanner.Scan(ctx, ports)
}

// QuickPortCheck checks if specific ports are open on a target (uses connect scan)
func QuickPortCheck(target string, ports ...int) (map[int]bool, error) {
	results, err := SimpleConnectScan(target, ports)
	if err != nil {
		return nil, err
	}
	
	portStatus := make(map[int]bool)
	
	for _, result := range results {
		// Initialize all ports as closed
		for _, port := range ports {
			portStatus[port] = false
		}
		
		// Mark open ports as true
		for _, openPort := range result.Open {
			portStatus[openPort] = true
		}
	}
	
	return portStatus, nil
}

// IsHostUp checks if a host is reachable by attempting to connect to common ports
func IsHostUp(target string) (bool, error) {
	commonPorts := []int{22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
	
	results, err := SimpleConnectScanWithTimeout(target, commonPorts, 3000)
	if err != nil {
		return false, err
	}
	
	for _, result := range results {
		if result.IsHostUp() {
			return true, nil
		}
	}
	
	return false, nil
}

// ScanCommonPorts scans the most common ports on a target
func ScanCommonPorts(target string) ([]Result, error) {
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5432, 5900, 8080, 8443,
	}
	
	return SimpleConnectScan(target, commonPorts)
}