package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/liamg/furious/scan"
)

func main() {
	fmt.Println("Furious Library Usage Examples")
	fmt.Println("==============================")

	// Example 1: Simple port check
	fmt.Println("\n1. Simple Port Check:")
	simplePortCheck()

	// Example 2: Check if host is up
	fmt.Println("\n2. Host Up Check:")
	hostUpCheck()

	// Example 3: Scan common ports
	fmt.Println("\n3. Common Ports Scan:")
	commonPortsScan()

	// Example 4: Custom configuration
	fmt.Println("\n4. Custom Configuration:")
	customConfigScan()

	// Example 5: Manual scanner usage (original approach, fixed)
	fmt.Println("\n5. Manual Scanner Usage (Fixed):")
	manualScannerUsage()

	// Example 6: SYN scan (requires root)
	fmt.Println("\n6. SYN Scan (requires root):")
	synScanExample()
}

// Example 1: Simple port check
func simplePortCheck() {
	target := "8.8.8.8"
	ports := []int{53, 80, 443}

	portStatus, err := scan.QuickPortCheck(target, ports...)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Port status for %s:\n", target)
	for port, isOpen := range portStatus {
		status := "CLOSED"
		if isOpen {
			status = "OPEN"
		}
		fmt.Printf("  Port %d: %s\n", port, status)
	}
}

// Example 2: Check if host is up
func hostUpCheck() {
	targets := []string{"8.8.8.8", "1.1.1.1", "192.0.2.1"} // Last one is RFC5737 test IP

	for _, target := range targets {
		isUp, err := scan.IsHostUp(target)
		if err != nil {
			log.Printf("Error checking %s: %v", target, err)
			continue
		}

		status := "DOWN"
		if isUp {
			status = "UP"
		}
		fmt.Printf("Host %s: %s\n", target, status)
	}
}

// Example 3: Scan common ports
func commonPortsScan() {
	target := "scanme.nmap.org"

	results, err := scan.ScanCommonPorts(target)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	for _, result := range results {
		fmt.Printf("Scan results for %s:\n", result.Host.String())
		if result.IsHostUp() {
			fmt.Printf("  Host is UP (latency: %v)\n", result.Latency)
			if len(result.Open) > 0 {
				fmt.Printf("  Open ports: %v\n", result.Open)
			}
		} else {
			fmt.Printf("  Host is DOWN\n")
		}
	}
}

// Example 4: Custom configuration
func customConfigScan() {
	target := "example.com"
	ports := []int{80, 443, 8080, 8443}

	// Create custom configuration
	config := scan.LibraryConfig{
		TimeoutMS: 5000, // 5 second timeout
		Workers:   100,  // 100 parallel workers
		ScanType:  "connect",
		Retries:   2, // 2 retries for reliability
	}

	scanner, err := scan.NewScannerFromConfig(target, config)
	if err != nil {
		log.Printf("Error creating scanner: %v", err)
		return
	}

	if err := scanner.Start(); err != nil {
		log.Printf("Error starting scanner: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, ports)
	if err != nil {
		log.Printf("Error scanning: %v", err)
		return
	}

	fmt.Printf("Custom scan results for %s:\n", target)
	for _, result := range results {
		if result.IsHostUp() {
			fmt.Printf("  Host: %s (UP)\n", result.Host.String())
			fmt.Printf("  Open: %v\n", result.Open)
			fmt.Printf("  Closed: %v\n", result.Closed)
		}
	}
}

// Example 5: Manual scanner usage (original approach, but fixed)
func manualScannerUsage() {
	target := "8.8.8.8"
	ports := []int{53, 80, 443}

	// FIXED: Use time.Duration instead of raw integer
	targetIterator := scan.NewTargetIterator(target)
	timeout := time.Duration(6000) * time.Millisecond // 6 seconds
	scanner := scan.NewConnectScanner(targetIterator, timeout, 1000)

	if err := scanner.Start(); err != nil {
		log.Printf("Error starting scanner: %v", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := scanner.Scan(ctx, ports)
	if err != nil {
		log.Printf("Error scanning: %v", err)
		return
	}

	fmt.Printf("Manual scanner results for %s:\n", target)
	for _, result := range results {
		// Use the scanner's output method or custom formatting
		if result.IsHostUp() {
			fmt.Printf("  Host %s is UP (latency: %v)\n", result.Host.String(), result.Latency)
			for _, port := range result.Open {
				fmt.Printf("    Port %d: OPEN\n", port)
			}
		} else {
			fmt.Printf("  Host %s is DOWN\n", result.Host.String())
		}
	}
}

// Example 6: SYN scan (requires root privileges)
func synScanExample() {
	target := "scanme.nmap.org"
	ports := []int{22, 80, 443}

	// Note: This will only work if running as root
	results, err := scan.SimpleSynScan(target, ports)
	if err != nil {
		log.Printf("SYN scan error (may need root privileges): %v", err)
		return
	}

	fmt.Printf("SYN scan results for %s:\n", target)
	for _, result := range results {
		if result.IsHostUp() {
			fmt.Printf("  Host: %s (UP)\n", result.Host.String())
			fmt.Printf("  Open: %v\n", result.Open)
			fmt.Printf("  Closed: %v\n", result.Closed)
			fmt.Printf("  Filtered: %v\n", result.Filtered)
		}
	}
}