package scan

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResultToJSON(t *testing.T) {
	// Create a test result
	result := Result{
		Host:     net.ParseIP("192.168.1.1"),
		Open:     []int{22, 80, 443},
		Closed:   []int{21, 23},
		Filtered: []int{8080},
		Latency:  time.Millisecond * 50,
		MAC:      "00:11:22:33:44:55",
		Name:     "test-host",
	}

	// Convert to JSON
	jsonData, err := result.ToJSON()
	require.NoError(t, err)

	// Parse the JSON to verify structure
	var jsonResult JSONResult
	err = json.Unmarshal(jsonData, &jsonResult)
	require.NoError(t, err)

	// Verify the JSON structure
	assert.Equal(t, "192.168.1.1", jsonResult.Host)
	assert.Equal(t, "up", jsonResult.Status)
	assert.Equal(t, float64(50), jsonResult.LatencyMs)
	assert.Equal(t, "00:11:22:33:44:55", jsonResult.MAC)
	assert.Equal(t, "test-host", jsonResult.Hostname)

	// Verify open ports
	require.Len(t, jsonResult.Open, 3)
	assert.Equal(t, 22, jsonResult.Open[0].Port)
	assert.Equal(t, "ssh", jsonResult.Open[0].Service)
	assert.Equal(t, 80, jsonResult.Open[1].Port)
	assert.Equal(t, "http", jsonResult.Open[1].Service)
	assert.Equal(t, 443, jsonResult.Open[2].Port)
	assert.Equal(t, "https", jsonResult.Open[2].Service)

	// Verify closed and filtered ports
	assert.Equal(t, []int{21, 23}, jsonResult.Closed)
	assert.Equal(t, []int{8080}, jsonResult.Filtered)
}

func TestResultToJSONDownHost(t *testing.T) {
	// Create a test result for a down host
	result := Result{
		Host:    net.ParseIP("192.168.1.100"),
		Latency: -1, // Indicates host is down
	}

	// Convert to JSON
	jsonData, err := result.ToJSON()
	require.NoError(t, err)

	// Parse the JSON to verify structure
	var jsonResult JSONResult
	err = json.Unmarshal(jsonData, &jsonResult)
	require.NoError(t, err)

	// Verify the JSON structure for down host
	assert.Equal(t, "192.168.1.100", jsonResult.Host)
	assert.Equal(t, "down", jsonResult.Status)
	assert.Equal(t, float64(0), jsonResult.LatencyMs)
	assert.Empty(t, jsonResult.Open)
}