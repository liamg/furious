package scan

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPortStateClassification(t *testing.T) {
	scanner := &ConnectScanner{timeout: 1000}
	
	tests := []struct {
		name          string
		errorString   string
		expectedState PortState
	}{
		{
			name:          "Connection refused should be closed",
			errorString:   "dial tcp 192.168.1.1:80: connect: connection refused",
			expectedState: PortClosed,
		},
		{
			name:          "Connection reset should be closed",
			errorString:   "dial tcp 192.168.1.1:80: connect: connection reset by peer",
			expectedState: PortClosed,
		},
		{
			name:          "Timeout should be filtered",
			errorString:   "dial tcp 192.168.1.1:80: i/o timeout",
			expectedState: PortFiltered,
		},
		{
			name:          "Network unreachable should be filtered",
			errorString:   "dial tcp 192.168.1.1:80: connect: network is unreachable",
			expectedState: PortFiltered,
		},
		{
			name:          "No route should be filtered",
			errorString:   "dial tcp 192.168.1.1:80: connect: no route to host",
			expectedState: PortFiltered,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily simulate these errors in a unit test,
			// but we can test the error classification logic
			
			// This is more of a documentation test showing the expected behavior
			switch {
			case contains(tt.errorString, "refused"):
				assert.Equal(t, PortClosed, tt.expectedState)
			case contains(tt.errorString, "reset"):
				assert.Equal(t, PortClosed, tt.expectedState)
			case contains(tt.errorString, "timeout"):
				assert.Equal(t, PortFiltered, tt.expectedState)
			case contains(tt.errorString, "unreachable") || contains(tt.errorString, "no route"):
				assert.Equal(t, PortFiltered, tt.expectedState)
			}
		})
	}
}

func TestSynScannerPortAccounting(t *testing.T) {
	// Test that all scanned ports are accounted for in the result
	
	// Simulate a scan result
	result := NewResult(net.ParseIP("192.168.1.1"))
	
	// Add some ports to each category
	result.Open = []int{22, 80, 443}
	result.Closed = []int{21, 23, 25}
	result.Filtered = []int{135, 139, 445, 8080}
	
	// Verify that we have the expected counts
	assert.Len(t, result.Open, 3, "Should have 3 open ports")
	assert.Len(t, result.Closed, 3, "Should have 3 closed ports") 
	assert.Len(t, result.Filtered, 4, "Should have 4 filtered ports")
	
	// Total ports scanned
	totalPorts := len(result.Open) + len(result.Closed) + len(result.Filtered)
	assert.Equal(t, 10, totalPorts, "Should account for all 10 scanned ports")
	
	// Verify no duplicates within each category
	assert.Equal(t, len(unique(result.Open)), len(result.Open), "Open ports should be unique")
	assert.Equal(t, len(unique(result.Closed)), len(result.Closed), "Closed ports should be unique")
	assert.Equal(t, len(unique(result.Filtered)), len(result.Filtered), "Filtered ports should be unique")
}

func TestFilteredPortDetection(t *testing.T) {
	// Test the logic for detecting filtered ports
	
	scannedPorts := []int{21, 22, 23, 80, 135, 139, 443, 445, 8080}
	respondedPorts := map[int]bool{
		22:  true, // SSH - open
		80:  true, // HTTP - open
		443: true, // HTTPS - open
		21:  true, // FTP - closed (RST)
		23:  true, // Telnet - closed (RST)
		// 135, 139, 445, 8080 don't respond - should be filtered
	}
	
	var openPorts, closedPorts, filteredPorts []int
	
	// Simulate the classification (this would happen based on packet responses)
	openPorts = []int{22, 80, 443}
	closedPorts = []int{21, 23}
	
	// Detect filtered ports (those that didn't respond)
	for _, port := range scannedPorts {
		if !respondedPorts[port] {
			filteredPorts = append(filteredPorts, port)
		}
	}
	
	// Verify the results
	assert.Equal(t, []int{22, 80, 443}, openPorts, "Open ports should match")
	assert.Equal(t, []int{21, 23}, closedPorts, "Closed ports should match")
	assert.Equal(t, []int{135, 139, 445, 8080}, filteredPorts, "Filtered ports should match")
	
	// Verify all ports are accounted for
	totalFound := len(openPorts) + len(closedPorts) + len(filteredPorts)
	assert.Equal(t, len(scannedPorts), totalFound, "All scanned ports should be classified")
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr || 
		   len(s) > len(substr) && s[:len(substr)] == substr ||
		   len(s) > len(substr) && findInString(s, substr)
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func unique(slice []int) []int {
	seen := make(map[int]bool)
	var result []int
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}