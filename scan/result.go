package scan

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type Result struct {
	Host         net.IP
	Open         []int
	Closed       []int
	Filtered     []int
	Manufacturer string
	MAC          string
	Latency      time.Duration
	Name         string
}

func NewResult(host net.IP) Result {
	return Result{
		Host:     host,
		Open:     []int{},
		Closed:   []int{},
		Filtered: []int{},
		Latency:  -1,
	}
}

func (r Result) IsHostUp() bool {
	return r.Latency > -1
}

func (r Result) String() string {

	text := fmt.Sprintf("Scan results for host %s\n", r.Host.String())

	if r.IsHostUp() {
		text = fmt.Sprintf("%s\tHost is up with %s latency\n", text, r.Latency.String())
	} else {
		text = fmt.Sprintf("%s\t%s\n", text, "Host is down")
	}

	if len(r.Open) > 0 {
		text = fmt.Sprintf(
			"%s\t%s\t%s\t%s\n",
			text,
			"PORT",
			"STATE",
			"SERVICE",
		)
	}

	for _, port := range r.Open {
		text = fmt.Sprintf(
			"%s\t%s\t%s\t%s\n",
			text,
			pad(fmt.Sprintf("%d/tcp", port), 10),
			pad("OPEN", 10),
			DescribePort(port),
		)
	}

	return text
}

func (r Result) ToJSON() (string, error) {
	// Create a custom struct for JSON output with proper formatting
	type jsonResult struct {
		Host         string `json:"host"`
		Open         []int  `json:"open_ports"`
		Closed       []int  `json:"closed_ports"`
		Filtered     []int  `json:"filtered_ports"`
		Manufacturer string `json:"manufacturer,omitempty"`
		MAC          string `json:"mac,omitempty"`
		LatencyMS    int64  `json:"latency_ms"`
		Name         string `json:"hostname,omitempty"`
		IsUp         bool   `json:"is_up"`
	}

	jr := jsonResult{
		Host:         r.Host.String(),
		Open:         r.Open,
		Closed:       r.Closed,
		Filtered:     r.Filtered,
		Manufacturer: r.Manufacturer,
		MAC:          r.MAC,
		LatencyMS:    r.Latency.Nanoseconds() / 1000000, // Convert to milliseconds
		Name:         r.Name,
		IsUp:         r.IsHostUp(),
	}

	jsonBytes, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func pad(input string, length int) string {
	for len(input) < length {
		input += " "
	}
	return input
}
