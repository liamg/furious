package scan

import (
	"net"
	"testing"
	"time"
)

func TestConnectScannerPortStates(t *testing.T) {
	ti := NewTargetIterator("127.0.0.1")
	scanner := NewConnectScanner(ti, time.Second*2, 10)

	tests := []struct {
		name        string
		target      string
		port        int
		expectState PortState
		expectError bool
	}{
		{
			name:        "Closed port should return PortClosed",
			target:      "127.0.0.1",
			port:        1, // Typically closed
			expectState: PortClosed,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.target)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.target)
			}

			state, err := scanner.scanPort(ip, tt.port)
			
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if state != tt.expectState {
				t.Errorf("Expected state %v, got %v", tt.expectState, state)
			}
		})
	}
}

func TestResultIsHostUp(t *testing.T) {
	tests := []struct {
		name     string
		latency  time.Duration
		expected bool
	}{
		{
			name:     "Negative latency should indicate host down",
			latency:  -1,
			expected: false,
		},
		{
			name:     "Zero latency should indicate host up",
			latency:  0,
			expected: true,
		},
		{
			name:     "Positive latency should indicate host up",
			latency:  time.Millisecond * 50,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Result{
				Host:    net.ParseIP("127.0.0.1"),
				Latency: tt.latency,
			}
			
			if result.IsHostUp() != tt.expected {
				t.Errorf("Expected IsHostUp() to return %v for latency %v", tt.expected, tt.latency)
			}
		})
	}
}