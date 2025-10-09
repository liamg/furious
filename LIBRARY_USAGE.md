# Furious Library Usage Guide

This guide helps you use Furious as a Go library in your own projects.

## Quick Start

### Installation

```bash
go get github.com/liamg/furious
```

### Simple Example

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/liamg/furious/scan"
)

func main() {
    // Check if specific ports are open
    portStatus, err := scan.QuickPortCheck("example.com", 80, 443)
    if err != nil {
        log.Fatal(err)
    }
    
    for port, isOpen := range portStatus {
        fmt.Printf("Port %d: %s\n", port, map[bool]string{true: "OPEN", false: "CLOSED"}[isOpen])
    }
}
```

## Common Issues and Solutions

### Issue 1: "Host is down" when it should be up

**Problem**: Your code shows "Host is down" but the furious CLI tool shows the host as up.

**Cause**: Incorrect timeout parameter. You're likely passing an integer instead of `time.Duration`.

**Wrong**:
```go
// This creates a 6000 nanosecond timeout (0.006ms)!
scanner := scan.NewConnectScanner(targetIterator, 6000, 1000)
```

**Correct**:
```go
// This creates a 6000 millisecond timeout (6 seconds)
timeout := time.Duration(6000) * time.Millisecond
scanner := scan.NewConnectScanner(targetIterator, timeout, 1000)

// Or use the library helpers:
results, err := scan.SimpleConnectScanWithTimeout("target.com", []int{80, 443}, 6000)
```

### Issue 2: Permission denied for SYN scans

**Problem**: SYN scans fail with permission errors.

**Solution**: SYN scans require root privileges. Either:

1. Run as root: `sudo go run main.go`
2. Use connect scans instead: `scan.SimpleConnectScan(target, ports)`
3. Check privileges in code:

```go
if os.Geteuid() != 0 {
    log.Println("SYN scan requires root privileges, falling back to connect scan")
    // Use connect scan instead
}
```

### Issue 3: Scans are too slow or too fast

**Problem**: Default settings don't match your needs.

**Solution**: Use custom configuration:

```go
config := scan.LibraryConfig{
    TimeoutMS: 10000,  // 10 second timeout for slow networks
    Workers:   50,     // Fewer workers for rate-limited targets
    ScanType:  "connect",
    Retries:   3,      // More retries for unreliable networks
}

scanner, err := scan.NewScannerFromConfig(target, config)
```

### Issue 4: Context cancellation

**Problem**: Need to cancel scans or set timeouts.

**Solution**: Use context properly:

```go
// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

results, err := scanner.Scan(ctx, ports)

// With manual cancellation
ctx, cancel := context.WithCancel(context.Background())
go func() {
    time.Sleep(10 * time.Second)
    cancel() // Cancel after 10 seconds
}()

results, err := scanner.Scan(ctx, ports)
```

## API Reference

### Simple Functions

#### `QuickPortCheck(target string, ports ...int) (map[int]bool, error)`
Quickly check if specific ports are open.

#### `IsHostUp(target string) (bool, error)`
Check if a host is reachable by testing common ports.

#### `SimpleConnectScan(target string, ports []int) ([]Result, error)`
Perform a connect scan with default settings.

#### `SimpleSynScan(target string, ports []int) ([]Result, error)`
Perform a SYN scan with default settings (requires root).

#### `ScanCommonPorts(target string) ([]Result, error)`
Scan the most common ports on a target.

### Configuration-Based API

#### `LibraryConfig`
```go
type LibraryConfig struct {
    TimeoutMS int    // Timeout in milliseconds
    Workers   int    // Number of parallel workers
    ScanType  string // "syn", "connect", or "device"
    Retries   int    // Number of retries
}
```

#### `NewScannerFromConfig(target string, config LibraryConfig) (Scanner, error)`
Create a scanner with custom configuration.

#### `DefaultLibraryConfig() LibraryConfig`
Get sensible default configuration.

### Manual Scanner API

For advanced usage, you can use the scanners directly:

```go
// Connect Scanner
targetIterator := scan.NewTargetIterator(target)
timeout := time.Duration(timeoutMS) * time.Millisecond
scanner := scan.NewConnectScanner(targetIterator, timeout, workers)

// SYN Scanner (requires root)
scanner := scan.NewSynScanner(targetIterator, timeout, workers)

// Device Scanner
scanner := scan.NewDeviceScanner(targetIterator, timeout)
```

## Examples

See the `examples/` directory for complete working examples:

- `examples/library_usage.go` - Comprehensive examples of all library features
- Simple port checking
- Host up detection
- Custom configuration
- Manual scanner usage
- Error handling

## Best Practices

1. **Always handle errors**: Network operations can fail in many ways
2. **Use appropriate timeouts**: Balance speed vs reliability
3. **Consider rate limiting**: Use fewer workers for rate-limited targets
4. **Use connect scans by default**: They don't require root privileges
5. **Test with known hosts first**: Verify your code works with reliable targets
6. **Use context for cancellation**: Allow users to cancel long-running scans

## Performance Tips

1. **Adjust worker count**: More workers = faster scans, but may trigger rate limiting
2. **Use appropriate timeouts**: Shorter timeouts = faster scans, but may miss slow responses
3. **Use SYN scans when possible**: Faster than connect scans, but requires root
4. **Batch operations**: Scan multiple ports at once rather than one by one
5. **Use retries for reliability**: Especially important for unreliable networks

## Troubleshooting

If you're still having issues:

1. Test with the CLI tool first: `furious -s connect target.com`
2. Check your timeout values: Make sure they're reasonable (1000-10000ms)
3. Verify network connectivity: Can you ping the target?
4. Check for rate limiting: Try with fewer workers or longer timeouts
5. Enable debug logging: Use the verbose flag or add logging to your code

For more help, see the examples or open an issue on GitHub.