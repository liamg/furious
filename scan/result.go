package scan

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type Result struct {
	Host         net.IP        `json:"host"`
	Open         []int         `json:"open_ports"`
	Closed       []int         `json:"closed_ports"`
	Filtered     []int         `json:"filtered_ports"`
	Manufacturer string        `json:"manufacturer,omitempty"`
	MAC          string        `json:"mac,omitempty"`
	Latency      time.Duration `json:"latency_ns"`
	Name         string        `json:"hostname,omitempty"`
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

func pad(input string, length int) string {
	for len(input) < length {
		input += " "
	}
	return input
}

// JSONResult represents a result in JSON-friendly format
type JSONResult struct {
	Host         string        `json:"host"`
	Status       string        `json:"status"`
	Open         []PortInfo    `json:"open_ports"`
	Closed       []int         `json:"closed_ports,omitempty"`
	Filtered     []int         `json:"filtered_ports,omitempty"`
	Manufacturer string        `json:"manufacturer,omitempty"`
	MAC          string        `json:"mac,omitempty"`
	LatencyMs    float64       `json:"latency_ms"`
	Hostname     string        `json:"hostname,omitempty"`
}

// PortInfo represents port information for JSON output
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// ToJSON converts Result to JSON format
func (r Result) ToJSON() ([]byte, error) {
	status := "down"
	if r.IsHostUp() {
		status = "up"
	}

	openPorts := make([]PortInfo, len(r.Open))
	for i, port := range r.Open {
		openPorts[i] = PortInfo{
			Port:    port,
			Service: DescribePort(port),
		}
	}

	latencyMs := float64(0)
	if r.Latency > 0 {
		latencyMs = float64(r.Latency.Nanoseconds()) / 1000000.0
	}

	jsonResult := JSONResult{
		Host:         r.Host.String(),
		Status:       status,
		Open:         openPorts,
		Closed:       r.Closed,
		Filtered:     r.Filtered,
		Manufacturer: r.Manufacturer,
		MAC:          r.MAC,
		LatencyMs:    latencyMs,
		Hostname:     r.Name,
	}

	return json.Marshal(jsonResult)
}
