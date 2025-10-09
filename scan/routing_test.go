package scan

import (
	"net"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDefaultInterface(t *testing.T) {
	iface, err := GetDefaultInterface()
	require.NoError(t, err)
	assert.NotNil(t, iface)
	assert.NotEmpty(t, iface.Name)
}

func TestGetRoute(t *testing.T) {
	// Test with a well-known public IP
	dst := net.ParseIP("8.8.8.8")
	require.NotNil(t, dst)

	routeInfo, err := GetRoute(dst)
	
	// On Windows, this might fail because we don't have route commands
	// but on Linux/macOS it should work
	if runtime.GOOS == "windows" {
		// On Windows, we expect this to fail gracefully
		if err != nil {
			t.Logf("Expected failure on Windows: %v", err)
			return
		}
	}
	
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		require.NoError(t, err)
		assert.NotNil(t, routeInfo)
		assert.NotNil(t, routeInfo.Interface)
		assert.NotNil(t, routeInfo.SrcIP)
		assert.NotEmpty(t, routeInfo.Interface.Name)
		
		t.Logf("Route info for %s:", dst.String())
		t.Logf("  Interface: %s", routeInfo.Interface.Name)
		t.Logf("  Source IP: %s", routeInfo.SrcIP.String())
		if routeInfo.Gateway != nil {
			t.Logf("  Gateway: %s", routeInfo.Gateway.String())
		}
	}
}

func TestParseLinuxRoute(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	
	// Test parsing Linux route output
	output := "192.168.1.1 via 192.168.1.254 dev eth0 src 192.168.1.100 uid 1000"
	
	routeInfo, err := parseLinuxRoute(output)
	require.NoError(t, err)
	
	assert.Equal(t, "192.168.1.254", routeInfo.Gateway.String())
	assert.Equal(t, "192.168.1.100", routeInfo.SrcIP.String())
	assert.Equal(t, "eth0", routeInfo.Interface.Name)
}func TestP
arseDarwinRoute(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}
	
	// Test parsing macOS route output
	output := `   route to: 8.8.8.8
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0        28         8         0      1500         0`
	
	routeInfo, err := parseDarwinRoute(output)
	require.NoError(t, err)
	
	assert.Equal(t, "192.168.1.1", routeInfo.Gateway.String())
	assert.Equal(t, "en0", routeInfo.Interface.Name)
	// Source IP will be determined from interface, so we just check it's not nil
	assert.NotNil(t, routeInfo.SrcIP)
}