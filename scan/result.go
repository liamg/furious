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
	Latency      time.Duration `json:"-" xml:"-"`
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

// MarshalJSON provides custom JSON marshaling for Result
func (r Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	return json.Marshal(&struct {
		Host      string `json:"host"`
		LatencyMS int64  `json:"latency_ms"`
		IsUp      bool   `json:"is_up"`
		*Alias
	}{
		Host:      r.Host.String(),
		LatencyMS: r.Latency.Nanoseconds() / 1000000, // Convert to milliseconds
		IsUp:      r.IsHostUp(),
		Alias:     (*Alias)(&r),
	})
}

// MarshalXML provides custom XML marshaling for Result
func (r Result) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Result
	aux := &struct {
		Host      string `xml:"host"`
		LatencyMS int64  `xml:"latency_ms"`
		IsUp      bool   `xml:"is_up"`
		*Alias
	}{
		Host:      r.Host.String(),
		LatencyMS: r.Latency.Nanoseconds() / 1000000, // Convert to milliseconds
		IsUp:      r.IsHostUp(),
		Alias:     (*Alias)(&r),
	}
	return e.EncodeElement(aux, start)
}

func pad(input string, length int) string {
	for len(input) < length {
		input += " "
	}
	return input
}
