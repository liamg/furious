# Cross-Platform Routing Fix for Issue #13

## Problem
The furious network scanner was crashing on macOS due to its dependency on the Linux-only `github.com/google/gopacket/routing` library. This library only works on Linux systems and causes runtime panics on macOS.

## Solution
Implemented a cross-platform routing abstraction that:

1. **Detects the host operating system** using `runtime.GOOS`
2. **Uses platform-specific implementations**:
   - **Linux**: Uses the original `github.com/google/gopacket/routing` library
   - **macOS**: Uses `golang.org/x/net/route` to access the native routing table
   - **Other platforms**: Returns a helpful error message suggesting to use connect scan

## Files Added/Modified

### New Files
- `scan/routing.go` - Cross-platform routing interface and factory
- `scan/routing_linux.go` - Linux-specific implementation using gopacket
- `scan/routing_darwin.go` - macOS-specific implementation using golang.org/x/net/route
- `scan/routing_fallback.go` - Fallback for unsupported platforms

### Modified Files
- `scan/scan-syn.go` - Updated to use new routing abstraction
- `go.mod` - Added `golang.org/x/net` dependency for macOS support

## Usage
The fix is transparent to users. The scanner will:
- Work normally on Linux and macOS
- Show a helpful error message on unsupported platforms, suggesting to use `-s connect` instead

## Testing
```bash
# On macOS/Linux - stealth scan should work
./furious -s stealth -p 80 target.com

# On any platform - connect scan works
./furious -s connect -p 80 target.com

# Debug mode shows platform-specific messages
./furious -v -s stealth -p 80 target.com
```

## Technical Details
The macOS implementation uses the BSD routing socket interface via `golang.org/x/net/route` to:
1. Fetch the routing table using `route.FetchRIB()`
2. Parse routing messages to find the best route for the destination
3. Extract interface, gateway, and source IP information
4. Handle both specific routes and default routes (0.0.0.0/0)

This provides the same functionality as the Linux gopacket routing library but uses macOS-native APIs.