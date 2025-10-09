package scan

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"time"
)

type Result struct {
	Host         net.IP        `json:"host" xml:"host"`
	Open         []int         `json:"open_ports" xml:"open_ports>port"`
	Closed       []int         `json:"closed_ports" xml:"closed_ports>port"`
	Filtered     []int         `json:"filtered_ports" xml:"filtered_ports>port"`
	Manufacturer string        `json:"manufacturer,omitempty" xml:"manufacturer,omitempty"`
	MAC          string        `json:"mac,omitempty" xml:"mac,omitempty"`
	Latency      time.Duration `json:"latency_ns" xml:"latency_ns"`
	Name         string        `json:"hostname,omitempty" xml:"hostname,omitempty"`
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

// StructuredResult represents a result in structured format (JSON/XML)
type StructuredResult struct {
	Host         string        `json:"host" xml:"host,attr"`
	Status       string        `json:"status" xml:"status,attr"`
	Latency      LatencyInfo   `json:"latency" xml:"latency"`
	Ports        PortsInfo     `json:"ports" xml:"ports"`
	HostInfo     HostInfo      `json:"host_info,omitempty" xml:"host_info,omitempty"`
	ScanTime     string        `json:"scan_time" xml:"scan_time,attr"`
}

// LatencyInfo represents latency information
type LatencyInfo struct {
	Milliseconds float64 `json:"ms" xml:"ms,attr"`
	Nanoseconds  int64   `json:"ns" xml:"ns,attr"`
}

// PortsInfo represents port scan results
type PortsInfo struct {
	Open     []PortDetail `json:"open,omitempty" xml:"open>port,omitempty"`
	Closed   []PortDetail `json:"closed,omitempty" xml:"closed>port,omitempty"`
	Filtered []PortDetail `json:"filtered,omitempty" xml:"filtered>port,omitempty"`
}

// PortDetail represents detailed port information
type PortDetail struct {
	Number   int    `json:"number" xml:"number,attr"`
	Protocol string `json:"protocol" xml:"protocol,attr"`
	Service  string `json:"service" xml:"service,attr"`
	State    string `json:"state" xml:"state,attr"`
}

// HostInfo represents additional host information
type HostInfo struct {
	MAC          string `json:"mac,omitempty" xml:"mac,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty" xml:"manufacturer,omitempty"`
	Hostname     string `json:"hostname,omitempty" xml:"hostname,omitempty"`
}

// ScanResults represents the complete scan results for structured output
type ScanResults struct {
	XMLName     xml.Name           `json:"-" xml:"furious_scan"`
	Version     string             `json:"version" xml:"version,attr"`
	ScanTime    string             `json:"scan_time" xml:"scan_time,attr"`
	Args        string             `json:"args" xml:"args,attr"`
	Results     []StructuredResult `json:"results" xml:"results>host"`
	Summary     ScanSummary        `json:"summary" xml:"summary"`
}

// ScanSummary represents scan summary information
type ScanSummary struct {
	HostsUp     int     `json:"hosts_up" xml:"hosts_up,attr"`
	HostsDown   int     `json:"hosts_down" xml:"hosts_down,attr"`
	HostsTotal  int     `json:"hosts_total" xml:"hosts_total,attr"`
	Duration    string  `json:"duration" xml:"duration,attr"`
	PortsScanned int    `json:"ports_scanned" xml:"ports_scanned,attr"`
}

// ToStructured converts Result to structured format
func (r Result) ToStructured() StructuredResult {
	status := "down"
	latency := LatencyInfo{Milliseconds: 0, Nanoseconds: 0}
	
	if r.IsHostUp() {
		status = "up"
		if r.Latency > 0 {
			latency.Nanoseconds = r.Latency.Nanoseconds()
			latency.Milliseconds = float64(r.Latency.Nanoseconds()) / 1000000.0
		}
	}

	// Convert ports to detailed format
	ports := PortsInfo{}
	
	for _, port := range r.Open {
		ports.Open = append(ports.Open, PortDetail{
			Number:   port,
			Protocol: "tcp",
			Service:  DescribePort(port),
			State:    "open",
		})
	}
	
	for _, port := range r.Closed {
		ports.Closed = append(ports.Closed, PortDetail{
			Number:   port,
			Protocol: "tcp",
			Service:  DescribePort(port),
			State:    "closed",
		})
	}
	
	for _, port := range r.Filtered {
		ports.Filtered = append(ports.Filtered, PortDetail{
			Number:   port,
			Protocol: "tcp",
			Service:  DescribePort(port),
			State:    "filtered",
		})
	}

	hostInfo := HostInfo{
		MAC:          r.MAC,
		Manufacturer: r.Manufacturer,
		Hostname:     r.Name,
	}

	return StructuredResult{
		Host:     r.Host.String(),
		Status:   status,
		Latency:  latency,
		Ports:    ports,
		HostInfo: hostInfo,
		ScanTime: time.Now().Format(time.RFC3339),
	}
}

// ToJSON converts Result to JSON format
func (r Result) ToJSON() ([]byte, error) {
	structured := r.ToStructured()
	return json.MarshalIndent(structured, "", "  ")
}

// ToXML converts Result to XML format
func (r Result) ToXML() ([]byte, error) {
	structured := r.ToStructured()
	return xml.MarshalIndent(structured, "", "  ")
}
