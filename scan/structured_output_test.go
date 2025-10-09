package scan

import (
	"encoding/json"
	"encoding/xml"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResultToStructured(t *testing.T) {
	// Create a test result
	result := Result{
		Host:         net.ParseIP("192.168.1.1"),
		Open:         []int{22, 80, 443},
		Closed:       []int{21, 23},
		Filtered:     []int{8080},
		Latency:      time.Millisecond * 50,
		MAC:          "00:11:22:33:44:55",
		Manufacturer: "Cisco Systems",
		Name:         "test-host.example.com",
	}

	// Convert to structured format
	structured := result.ToStructured()

	// Verify the structured format
	assert.Equal(t, "192.168.1.1", structured.Host)
	assert.Equal(t, "up", structured.Status)
	assert.Equal(t, float64(50), structured.Latency.Milliseconds)
	assert.Equal(t, int64(50000000), structured.Latency.Nanoseconds)

	// Verify open ports
	require.Len(t, structured.Ports.Open, 3)
	assert.Equal(t, 22, structured.Ports.Open[0].Number)
	assert.Equal(t, "tcp", structured.Ports.Open[0].Protocol)
	assert.Equal(t, "ssh", structured.Ports.Open[0].Service)
	assert.Equal(t, "open", structured.Ports.Open[0].State)

	// Verify closed ports
	require.Len(t, structured.Ports.Closed, 2)
	assert.Equal(t, 21, structured.Ports.Closed[0].Number)
	assert.Equal(t, "closed", structured.Ports.Closed[0].State)

	// Verify filtered ports
	require.Len(t, structured.Ports.Filtered, 1)
	assert.Equal(t, 8080, structured.Ports.Filtered[0].Number)
	assert.Equal(t, "filtered", structured.Ports.Filtered[0].State)

	// Verify host info
	assert.Equal(t, "00:11:22:33:44:55", structured.HostInfo.MAC)
	assert.Equal(t, "Cisco Systems", structured.HostInfo.Manufacturer)
	assert.Equal(t, "test-host.example.com", structured.HostInfo.Hostname)
}

func TestResultToJSON(t *testing.T) {
	result := Result{
		Host:    net.ParseIP("8.8.8.8"),
		Open:    []int{53, 443},
		Latency: time.Millisecond * 25,
	}

	jsonData, err := result.ToJSON()
	require.NoError(t, err)

	// Parse the JSON to verify structure
	var structured StructuredResult
	err = json.Unmarshal(jsonData, &structured)
	require.NoError(t, err)

	assert.Equal(t, "8.8.8.8", structured.Host)
	assert.Equal(t, "up", structured.Status)
	assert.Equal(t, float64(25), structured.Latency.Milliseconds)
	require.Len(t, structured.Ports.Open, 2)
	assert.Equal(t, 53, structured.Ports.Open[0].Number)
	assert.Equal(t, "domain", structured.Ports.Open[0].Service)
}

func TestResultToXML(t *testing.T) {
	result := Result{
		Host:    net.ParseIP("192.168.1.100"),
		Closed:  []int{80, 443},
		Latency: time.Millisecond * 100,
	}

	xmlData, err := result.ToXML()
	require.NoError(t, err)

	// Parse the XML to verify structure
	var structured StructuredResult
	err = xml.Unmarshal(xmlData, &structured)
	require.NoError(t, err)

	assert.Equal(t, "192.168.1.100", structured.Host)
	assert.Equal(t, "up", structured.Status)
	assert.Equal(t, float64(100), structured.Latency.Milliseconds)
	require.Len(t, structured.Ports.Closed, 2)
	assert.Equal(t, 80, structured.Ports.Closed[0].Number)
	assert.Equal(t, "http", structured.Ports.Closed[0].Service)
}

func TestScanResultsStructure(t *testing.T) {
	results := []Result{
		{
			Host:    net.ParseIP("192.168.1.1"),
			Open:    []int{22, 80},
			Latency: time.Millisecond * 30,
		},
		{
			Host:    net.ParseIP("192.168.1.2"),
			Closed:  []int{22, 80},
			Latency: time.Millisecond * 45,
		},
	}

	// Convert to structured results
	structuredResults := make([]StructuredResult, 0, len(results))
	hostsUp := 0
	
	for _, result := range results {
		structured := result.ToStructured()
		structuredResults = append(structuredResults, structured)
		if result.IsHostUp() {
			hostsUp++
		}
	}

	scanResults := ScanResults{
		Version:  "test-version",
		ScanTime: "2023-01-01T12:00:00Z",
		Args:     "192.168.1.0/24",
		Results:  structuredResults,
		Summary: ScanSummary{
			HostsUp:      hostsUp,
			HostsDown:    len(results) - hostsUp,
			HostsTotal:   len(results),
			Duration:     "2.5s",
			PortsScanned: 2,
		},
	}

	// Test JSON marshaling
	jsonData, err := json.MarshalIndent(scanResults, "", "  ")
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), "test-version")
	assert.Contains(t, string(jsonData), "192.168.1.1")

	// Test XML marshaling
	xmlData, err := xml.MarshalIndent(scanResults, "", "  ")
	require.NoError(t, err)
	assert.Contains(t, string(xmlData), "furious_scan")
	assert.Contains(t, string(xmlData), "192.168.1.1")
}

func TestResultDownHost(t *testing.T) {
	// Test with a down host (negative latency)
	result := Result{
		Host:    net.ParseIP("192.168.1.200"),
		Latency: -1, // Indicates host is down
	}

	structured := result.ToStructured()
	assert.Equal(t, "192.168.1.200", structured.Host)
	assert.Equal(t, "down", structured.Status)
	assert.Equal(t, float64(0), structured.Latency.Milliseconds)
	assert.Equal(t, int64(0), structured.Latency.Nanoseconds)
}