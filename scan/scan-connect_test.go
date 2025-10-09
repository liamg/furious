package scan

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectScannerHostDetection(t *testing.T) {
	// Test with a well-known host that should be up
	ti := NewTargetIterator("8.8.8.8")
	scanner := NewConnectScanner(ti, time.Second*2, 10)
	
	err := scanner.Start()
	require.NoError(t, err)
	
	ctx := context.Background()
	// Test with a port that's likely to be closed but host should be up
	results, err := scanner.Scan(ctx, []int{12345}) // Random high port
	require.NoError(t, err)
	require.Len(t, results, 1)
	
	result := results[0]
	// Host should be detected as up even if the port is closed
	assert.True(t, result.IsHostUp(), "Host should be detected as up even with closed ports")
	assert.True(t, result.Latency > 0, "Latency should be positive for up host")
}

func TestConnectScannerPortStates(t *testing.T) {
	scanner := &ConnectScanner{timeout: time.Second}
	
	// Test with a known open port (Google DNS)
	state, err := scanner.scanPort(net.ParseIP("8.8.8.8"), 53)
	require.NoError(t, err)
	assert.Equal(t, PortOpen, state)
	
	// Test with a likely closed port
	state, err = scanner.scanPort(net.ParseIP("8.8.8.8"), 12345)
	require.NoError(t, err)
	// Should be PortClosed (connection refused) not PortUnknown
	assert.Equal(t, PortClosed, state)
}