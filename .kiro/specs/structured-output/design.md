# Design Document

## Overview

The structured output feature adds JSON and XML export capabilities to furious, enabling machine-readable output for automation and integration. The design extends the existing scanner architecture with minimal changes while providing comprehensive, consistent structured data across all scanner types.

## Architecture

### High-Level Design

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Parser    │───▶│  Output Manager  │───▶│ Format Writers  │
│  (--json/-j)    │    │                  │    │  - JSON Writer  │
│  (--xml/-x)     │    │                  │    │  - XML Writer   │
└─────────────────┘    └──────────────────┘    │  - Text Writer  │
                                ▲               └─────────────────┘
                                │
                       ┌──────────────────┐
                       │   Scanner Core   │
                       │  (unchanged)     │
                       └──────────────────┘
```

### Design Principles

1. **Non-intrusive**: Minimal changes to existing scanner logic
2. **Consistent**: Same data structure across all scanner types
3. **Extensible**: Easy to add new output formats in the future
4. **Backward Compatible**: No changes to existing text output behavior

## Components and Interfaces

### 1. Output Manager Interface

```go
type OutputManager interface {
    SetFormat(format OutputFormat) error
    WriteResults(results []Result, metadata ScanMetadata) error
    WriteError(err error) error
}

type OutputFormat int
const (
    FormatText OutputFormat = iota
    FormatJSON
    FormatXML
)
```

### 2. Enhanced Result Structure

The existing `Result` struct will be extended with JSON/XML tags:

```go
type Result struct {
    Host         net.IP        `json:"host" xml:"host"`
    Open         []int         `json:"open_ports" xml:"open_ports>port"`
    Closed       []int         `json:"closed_ports" xml:"closed_ports>port"`
    Filtered     []int         `json:"filtered_ports" xml:"filtered_ports>port"`
    Manufacturer string        `json:"manufacturer,omitempty" xml:"manufacturer,omitempty"`
    MAC          string        `json:"mac,omitempty" xml:"mac,omitempty"`
    Latency      time.Duration `json:"latency_ms" xml:"latency_ms"`
    Name         string        `json:"hostname,omitempty" xml:"hostname,omitempty"`
    IsUp         bool          `json:"is_up" xml:"is_up"`
}
```

### 3. Scan Metadata Structure

```go
type ScanMetadata struct {
    Version     string        `json:"version" xml:"version"`
    StartTime   time.Time     `json:"start_time" xml:"start_time"`
    EndTime     time.Time     `json:"end_time" xml:"end_time"`
    Duration    time.Duration `json:"duration_ms" xml:"duration_ms"`
    ScanType    string        `json:"scan_type" xml:"scan_type"`
    Targets     []string      `json:"targets" xml:"targets>target"`
    Ports       []int         `json:"ports" xml:"ports>port"`
    Timeout     int           `json:"timeout_ms" xml:"timeout_ms"`
    Parallelism int           `json:"parallelism" xml:"parallelism"`
    Summary     ScanSummary   `json:"summary" xml:"summary"`
}

type ScanSummary struct {
    TotalHosts    int `json:"total_hosts" xml:"total_hosts"`
    HostsUp       int `json:"hosts_up" xml:"hosts_up"`
    HostsDown     int `json:"hosts_down" xml:"hosts_down"`
    TotalPorts    int `json:"total_ports_scanned" xml:"total_ports_scanned"`
    OpenPorts     int `json:"open_ports" xml:"open_ports"`
    ClosedPorts   int `json:"closed_ports" xml:"closed_ports"`
    FilteredPorts int `json:"filtered_ports" xml:"filtered_ports"`
}
```

### 4. Structured Output Container

```go
type StructuredOutput struct {
    Metadata ScanMetadata `json:"metadata" xml:"metadata"`
    Results  []Result     `json:"results" xml:"results>result"`
}
```

## Data Models

### JSON Output Schema

```json
{
  "metadata": {
    "version": "1.0.0",
    "start_time": "2023-10-09T12:00:00Z",
    "end_time": "2023-10-09T12:00:05Z",
    "duration_ms": 5000,
    "scan_type": "connect",
    "targets": ["example.com", "192.168.1.1"],
    "ports": [22, 80, 443],
    "timeout_ms": 2000,
    "parallelism": 500,
    "summary": {
      "total_hosts": 2,
      "hosts_up": 1,
      "hosts_down": 1,
      "total_ports_scanned": 6,
      "open_ports": 2,
      "closed_ports": 1,
      "filtered_ports": 0
    }
  },
  "results": [
    {
      "host": "93.184.216.34",
      "open_ports": [80, 443],
      "closed_ports": [22],
      "filtered_ports": [],
      "latency_ms": 45,
      "hostname": "example.com",
      "is_up": true
    }
  ]
}
```

### XML Output Schema

```xml
<?xml version="1.0" encoding="UTF-8"?>
<furious_scan>
  <metadata>
    <version>1.0.0</version>
    <start_time>2023-10-09T12:00:00Z</start_time>
    <end_time>2023-10-09T12:00:05Z</end_time>
    <duration_ms>5000</duration_ms>
    <scan_type>connect</scan_type>
    <targets>
      <target>example.com</target>
      <target>192.168.1.1</target>
    </targets>
    <ports>
      <port>22</port>
      <port>80</port>
      <port>443</port>
    </ports>
    <timeout_ms>2000</timeout_ms>
    <parallelism>500</parallelism>
    <summary>
      <total_hosts>2</total_hosts>
      <hosts_up>1</hosts_up>
      <hosts_down>1</hosts_down>
      <total_ports_scanned>6</total_ports_scanned>
      <open_ports>2</open_ports>
      <closed_ports>1</closed_ports>
      <filtered_ports>0</filtered_ports>
    </summary>
  </metadata>
  <results>
    <result>
      <host>93.184.216.34</host>
      <open_ports>
        <port>80</port>
        <port>443</port>
      </open_ports>
      <closed_ports>
        <port>22</port>
      </closed_ports>
      <filtered_ports/>
      <latency_ms>45</latency_ms>
      <hostname>example.com</hostname>
      <is_up>true</is_up>
    </result>
  </results>
</furious_scan>
```

## Error Handling

### Format Validation
- JSON output validated using Go's `encoding/json` package
- XML output validated using Go's `encoding/xml` package
- Invalid structured output triggers error with fallback to text format

### Conflicting Flags
- Multiple output format flags (--json and --xml) result in clear error message
- Error message suggests using only one format flag at a time

### Missing Data Handling
- Optional fields use `omitempty` tags to exclude null/empty values
- Required fields always present with appropriate zero values
- Device-specific fields (MAC, manufacturer) only included when available

## Testing Strategy

### Unit Tests
1. **Output Format Selection**
   - Test CLI flag parsing for --json/-j and --xml/-x
   - Test error handling for conflicting format flags
   - Test default text format behavior

2. **JSON Output Generation**
   - Test valid JSON generation for single and multiple hosts
   - Test JSON schema compliance with various scan results
   - Test handling of missing/optional fields

3. **XML Output Generation**
   - Test valid XML generation with proper structure
   - Test XML schema compliance and well-formedness
   - Test handling of special characters and encoding

4. **Data Consistency**
   - Test that structured output contains same data as text output
   - Test metadata accuracy and completeness
   - Test summary statistics calculation

### Integration Tests
1. **Scanner Compatibility**
   - Test JSON/XML output with connect scanner
   - Test JSON/XML output with stealth scanner (when available)
   - Test JSON/XML output with device scanner

2. **Real-world Scenarios**
   - Test with various target types (IP, hostname, CIDR)
   - Test with different port specifications
   - Test with various timeout and parallelism settings

### Performance Tests
1. **Output Generation Performance**
   - Measure JSON generation time for large result sets
   - Measure XML generation time for large result sets
   - Compare structured output performance vs text output

## Implementation Phases

### Phase 1: Core Infrastructure
- Add output format flags to CLI
- Create OutputManager interface and basic implementations
- Extend Result struct with JSON/XML tags

### Phase 2: JSON Support
- Implement JSON output writer
- Add metadata collection and JSON serialization
- Integrate with existing scanners

### Phase 3: XML Support
- Implement XML output writer
- Add XML-specific formatting and structure
- Ensure XML validation and well-formedness

### Phase 4: Testing and Polish
- Comprehensive unit and integration tests
- Performance optimization
- Documentation and examples

## Backward Compatibility

- Default behavior unchanged (text output)
- All existing CLI flags and options remain functional
- No changes to existing scanner interfaces
- Text output format and content unchanged