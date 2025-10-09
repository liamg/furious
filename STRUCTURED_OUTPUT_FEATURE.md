# Structured Output Feature - Issue #11

## Overview
This feature adds JSON and XML structured output support to furious, enabling machine-readable results for automation, scripting, and integration with other security tools.

## Usage

### JSON Output
```bash
# Generate JSON output
furious --json -s connect -p 80,443 example.com
furious -j -s connect -p 22,80,443,8080 192.168.1.0/24

# JSON output with specific scan type
furious --json --scan-type stealth -p 1-1000 target.com
```

### XML Output
```bash
# Generate XML output
furious --xml -s connect -p 80,443 example.com
furious -x -s device 192.168.1.0/24

# XML output with custom ports
furious --xml -p 22,80,443,8080-8090 multiple.targets.com
```

### Text Output (Default)
```bash
# Traditional text output (unchanged)
furious -s connect -p 80,443 example.com
```

## Output Formats

### JSON Schema
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

### XML Schema
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

## Features

### Comprehensive Metadata
- **Scan Information**: Version, start/end times, duration, scan type
- **Parameters**: Targets, ports, timeout, parallelism settings
- **Statistics**: Host counts, port state summaries

### Consistent Data Structure
- **Same schema** across all scanner types (connect, stealth, device)
- **Device-specific fields** included when available (MAC, manufacturer)
- **Proper data types** with appropriate null/empty handling

### Error Handling
- **Format validation** ensures valid JSON/XML output
- **Conflicting flags** detection (--json and --xml together)
- **Graceful degradation** with clear error messages

## Command Line Options

| Flag | Short | Description |
|------|-------|-------------|
| `--json` | `-j` | Output results in JSON format |
| `--xml` | `-x` | Output results in XML format |

### Validation Rules
- Cannot specify both `--json` and `--xml` simultaneously
- Structured output suppresses normal text output
- All existing flags and options remain compatible

## Integration Examples

### Parse JSON with jq
```bash
# Extract open ports from all hosts
furious --json -s connect example.com | jq '.results[].open_ports[]'

# Get summary statistics
furious --json -s connect targets.txt | jq '.metadata.summary'

# Filter only hosts that are up
furious --json -s connect network.com | jq '.results[] | select(.is_up == true)'
```

### Parse XML with xmllint
```bash
# Extract host information
furious --xml -s connect example.com | xmllint --xpath "//result/host/text()" -

# Get scan duration
furious --xml -s connect example.com | xmllint --xpath "//metadata/duration_ms/text()" -
```

### Python Integration
```python
import json
import subprocess

# Run furious and parse JSON output
result = subprocess.run(['furious', '--json', '-s', 'connect', 'example.com'], 
                       capture_output=True, text=True)
scan_data = json.loads(result.stdout)

# Process results
for host_result in scan_data['results']:
    if host_result['is_up']:
        print(f"Host {host_result['host']} has {len(host_result['open_ports'])} open ports")
```

## Implementation Details

### Files Modified/Added
- `cmd/root.go` - Added CLI flags and output format selection
- `scan/output.go` - Output manager interface and implementations
- `scan/result.go` - Added JSON/XML marshaling to Result struct

### Architecture
- **OutputManager interface** provides pluggable output formats
- **Custom marshaling** handles IP addresses and duration formatting
- **Metadata collection** gathers comprehensive scan information
- **Summary calculation** provides aggregated statistics

### Backward Compatibility
- ✅ Default behavior unchanged (text output)
- ✅ All existing CLI flags remain functional
- ✅ No changes to scanner interfaces or logic
- ✅ Text output format and content unchanged

## Error Handling

### Format Conflicts
```bash
$ furious --json --xml example.com
Error: Cannot specify both --json and --xml output formats. Please choose one.
```

### Invalid Data
- JSON/XML validation ensures well-formed output
- Missing optional fields handled gracefully with omitempty tags
- Network errors reported in structured format when possible

## Performance
- Structured output generation adds minimal overhead
- Memory usage scales linearly with result set size
- JSON/XML marshaling optimized for large scan results