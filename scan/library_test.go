package scan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLibraryConfig(t *testing.T) {
	config := DefaultLibraryConfig()
	
	assert.Equal(t, 2000, config.TimeoutMS)
	assert.Equal(t, 500, config.Workers)
	assert.Equal(t, "connect", config.ScanType)
	assert.Equal(t, 1, config.Retries)
}

func TestNewScannerFromConfig(t *testing.T) {
	target := "127.0.0.1"
	
	// Test connect scanner creation
	config := LibraryConfig{
		TimeoutMS: 1000,
		Workers:   100,
		ScanType:  "connect",
		Retries:   1,
	}
	
	scanner, err := NewScannerFromConfig(target, config)
	require.NoError(t, err)
	assert.NotNil(t, scanner)
	
	// Verify it's a ConnectScanner
	connectScanner, ok := scanner.(*ConnectScanner)
	assert.True(t, ok, "Should create a ConnectScanner")
	assert.Equal(t, time.Second, connectScanner.timeout)
	assert.Equal(t, 100, connectScanner.maxRoutines)
}

func TestNewScannerFromConfigSyn(t *testing.T) {
	target := "127.0.0.1"
	
	// Test SYN scanner creation
	config := LibraryConfig{
		TimeoutMS: 2000,
		Workers:   200,
		ScanType:  "syn",
		Retries:   2,
	}
	
	scanner, err := NewScannerFromConfig(target, config)
	require.NoError(t, err)
	assert.NotNil(t, scanner)
	
	// Verify it's a SynScanner
	synScanner, ok := scanner.(*SynScanner)
	assert.True(t, ok, "Should create a SynScanner")
	assert.Equal(t, 2*time.Second, synScanner.timeout)
	assert.Equal(t, 200, synScanner.maxRoutines)
}

func TestNewScannerFromConfigDevice(t *testing.T) {
	target := "127.0.0.1"
	
	// Test device scanner creation
	config := LibraryConfig{
		TimeoutMS: 3000,
		Workers:   50, // Not used for device scanner
		ScanType:  "device",
		Retries:   1,
	}
	
	scanner, err := NewScannerFromConfig(target, config)
	require.NoError(t, err)
	assert.NotNil(t, scanner)
	
	// Verify it's a DeviceScanner
	deviceScanner, ok := scanner.(*DeviceScanner)
	assert.True(t, ok, "Should create a DeviceScanner")
	assert.Equal(t, 3*time.Second, deviceScanner.timeout)
}

func TestSimpleConnectScan(t *testing.T) {
	// Test with localhost (should be reachable)
	target := "127.0.0.1"
	ports := []int{22, 80} // Common ports that might be open
	
	results, err := SimpleConnectScan(target, ports)
	require.NoError(t, err)
	require.Len(t, results, 1)
	
	result := results[0]
	assert.Equal(t, target, result.Host.String())
	
	// Should account for all scanned ports
	totalPorts := len(result.Open) + len(result.Closed) + len(result.Filtered)
	assert.Equal(t, len(ports), totalPorts, "All scanned ports should be accounted for")
}

func TestQuickPortCheck(t *testing.T) {
	// Test with a reliable host
	target := "8.8.8.8"
	ports := []int{53, 80} // DNS should be open, HTTP might be
	
	portStatus, err := QuickPortCheck(target, ports...)
	require.NoError(t, err)
	
	// Should have status for all requested ports
	assert.Len(t, portStatus, len(ports))
	
	for _, port := range ports {
		_, exists := portStatus[port]
		assert.True(t, exists, "Should have status for port %d", port)
	}
}

func TestIsHostUp(t *testing.T) {
	// Test with known good host
	isUp, err := IsHostUp("8.8.8.8")
	require.NoError(t, err)
	assert.True(t, isUp, "8.8.8.8 should be up")
	
	// Test with likely non-existent host
	isUp, err = IsHostUp("192.0.2.1") // RFC5737 test IP
	// This might error or return false, both are acceptable
	if err == nil {
		assert.False(t, isUp, "Test IP should not be up")
	}
}

func TestScanCommonPorts(t *testing.T) {
	// Test with localhost
	target := "127.0.0.1"
	
	results, err := ScanCommonPorts(target)
	require.NoError(t, err)
	require.Len(t, results, 1)
	
	result := results[0]
	assert.Equal(t, target, result.Host.String())
	
	// Should have scanned the common ports (22 ports defined in the function)
	totalPorts := len(result.Open) + len(result.Closed) + len(result.Filtered)
	assert.Equal(t, 22, totalPorts, "Should scan all common ports")
}

func TestTimeoutConversion(t *testing.T) {
	// Test that timeout conversion works correctly
	config := LibraryConfig{
		TimeoutMS: 5000, // 5 seconds
		Workers:   100,
		ScanType:  "connect",
	}
	
	scanner, err := NewScannerFromConfig("127.0.0.1", config)
	require.NoError(t, err)
	
	connectScanner := scanner.(*ConnectScanner)
	expectedTimeout := 5 * time.Second
	assert.Equal(t, expectedTimeout, connectScanner.timeout)
}

func TestInvalidScanType(t *testing.T) {
	// Test with invalid scan type - should default to connect
	config := LibraryConfig{
		TimeoutMS: 1000,
		Workers:   100,
		ScanType:  "invalid",
	}
	
	scanner, err := NewScannerFromConfig("127.0.0.1", config)
	require.NoError(t, err)
	
	// Should default to ConnectScanner
	_, ok := scanner.(*ConnectScanner)
	assert.True(t, ok, "Should default to ConnectScanner for invalid scan type")
}