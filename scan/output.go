package scan

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"
)

// OutputFormat represents the different output formats supported
type OutputFormat int

const (
	FormatText OutputFormat = iota
	FormatJSON
	FormatXML
)

// OutputManager interface for handling different output formats
type OutputManager interface {
	WriteResults(results []Result, metadata ScanMetadata) error
	WriteError(err error) error
}

// ScanMetadata contains information about the scan execution
type ScanMetadata struct {
	Version     string        `json:"version" xml:"version"`
	StartTime   time.Time     `json:"start_time" xml:"start_time"`
	EndTime     time.Time     `json:"end_time" xml:"end_time"`
	Duration    time.Duration `json:"-" xml:"-"`
	ScanType    string        `json:"scan_type" xml:"scan_type"`
	Targets     []string      `json:"targets" xml:"targets>target"`
	Ports       []int         `json:"ports" xml:"ports>port"`
	Timeout     int           `json:"timeout_ms" xml:"timeout_ms"`
	Parallelism int           `json:"parallelism" xml:"parallelism"`
	Summary     ScanSummary   `json:"summary" xml:"summary"`
}

// MarshalJSON provides custom JSON marshaling for ScanMetadata
func (s ScanMetadata) MarshalJSON() ([]byte, error) {
	type Alias ScanMetadata
	return json.Marshal(&struct {
		DurationMS int64 `json:"duration_ms"`
		*Alias
	}{
		DurationMS: s.Duration.Nanoseconds() / 1000000, // Convert to milliseconds
		Alias:      (*Alias)(&s),
	})
}

// MarshalXML provides custom XML marshaling for ScanMetadata
func (s ScanMetadata) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias ScanMetadata
	aux := &struct {
		DurationMS int64 `xml:"duration_ms"`
		*Alias
	}{
		DurationMS: s.Duration.Nanoseconds() / 1000000, // Convert to milliseconds
		Alias:      (*Alias)(&s),
	}
	return e.EncodeElement(aux, start)
}

// ScanSummary contains aggregated statistics about the scan
type ScanSummary struct {
	TotalHosts    int `json:"total_hosts" xml:"total_hosts"`
	HostsUp       int `json:"hosts_up" xml:"hosts_up"`
	HostsDown     int `json:"hosts_down" xml:"hosts_down"`
	TotalPorts    int `json:"total_ports_scanned" xml:"total_ports_scanned"`
	OpenPorts     int `json:"open_ports" xml:"open_ports"`
	ClosedPorts   int `json:"closed_ports" xml:"closed_ports"`
	FilteredPorts int `json:"filtered_ports" xml:"filtered_ports"`
}

// StructuredOutput is the container for JSON/XML output
type StructuredOutput struct {
	XMLName  xml.Name     `json:"-" xml:"furious_scan"`
	Metadata ScanMetadata `json:"metadata" xml:"metadata"`
	Results  []Result     `json:"results" xml:"results>result"`
}

// NewOutputManager creates an appropriate output manager based on format
func NewOutputManager(format OutputFormat) OutputManager {
	switch format {
	case FormatJSON:
		return &JSONOutputManager{}
	case FormatXML:
		return &XMLOutputManager{}
	default:
		return &TextOutputManager{}
	}
}

// TextOutputManager handles traditional text output
type TextOutputManager struct{}

func (t *TextOutputManager) WriteResults(results []Result, metadata ScanMetadata) error {
	// Use existing text output format
	for _, result := range results {
		fmt.Println(result.String())
	}
	return nil
}

func (t *TextOutputManager) WriteError(err error) error {
	fmt.Printf("Error: %v\n", err)
	return nil
}

// JSONOutputManager handles JSON output
type JSONOutputManager struct{}

func (j *JSONOutputManager) WriteResults(results []Result, metadata ScanMetadata) error {
	output := StructuredOutput{
		Metadata: metadata,
		Results:  results,
	}
	
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	
	fmt.Println(string(jsonData))
	return nil
}

func (j *JSONOutputManager) WriteError(err error) error {
	errorOutput := map[string]string{"error": err.Error()}
	jsonData, marshalErr := json.MarshalIndent(errorOutput, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal error JSON: %v", marshalErr)
	}
	fmt.Println(string(jsonData))
	return nil
}

// XMLOutputManager handles XML output
type XMLOutputManager struct{}

func (x *XMLOutputManager) WriteResults(results []Result, metadata ScanMetadata) error {
	output := StructuredOutput{
		Metadata: metadata,
		Results:  results,
	}
	
	xmlData, err := xml.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XML: %v", err)
	}
	
	fmt.Printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n%s\n", string(xmlData))
	return nil
}

func (x *XMLOutputManager) WriteError(err error) error {
	errorOutput := struct {
		XMLName xml.Name `xml:"error"`
		Message string   `xml:"message"`
	}{
		Message: err.Error(),
	}
	
	xmlData, marshalErr := xml.MarshalIndent(errorOutput, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal error XML: %v", marshalErr)
	}
	
	fmt.Printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n%s\n", string(xmlData))
	return nil
}