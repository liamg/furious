# Setup Instructions for Pull Request

## After forking the repository on GitHub:

1. Add your fork as a remote (replace YOUR_USERNAME):
```bash
git remote add fork https://github.com/YOUR_USERNAME/furious.git
```

2. Push your branch to your fork:
```bash
git push fork fix-major-issues
```

3. Go to your fork on GitHub and click "Create Pull Request"

## Pull Request Details:

**Title:** Fix major issues: host detection, filtered ports, and add JSON output

**Description:**
This PR addresses three critical issues from the repository:

### Issues Fixed:
- **#12: Connect scan always returns "Host is down"** ✅
  - Enhanced latency tracking to properly detect host availability
  - Fixed error handling in connect scanner worker routines
  - Hosts now correctly show as "up" when they respond

- **#7: Filtered ports not populated** ✅  
  - Added proper timeout detection to classify ports as filtered
  - Enhanced port state classification logic
  - Filtered ports now correctly identified and displayed

- **#14: Add JSON output support** ✅
  - Implemented new `-j/--json` flag for structured output
  - JSON schema includes host, ports, latency, and status
  - Maintains full backward compatibility

### Technical Improvements:
- Better connection error classification (timeout vs refused vs unknown)
- Enhanced port state detection logic
- Improved scanner interface with JSON support methods
- More accurate response time measurement

### Testing:
- ✅ Connect scanning works properly, hosts detected as up
- ✅ Filtered ports correctly identified 
- ✅ JSON output provides clean, structured format
- ✅ Backward compatibility maintained
- ✅ Performance improvements verified

### Example Usage:
```bash
# Regular output
./furious -s connect -p 80,443,8080 google.com

# JSON output  
./furious -s connect -p 80,443,8080 -j google.com
```

This PR significantly improves the reliability and functionality of the scanner.

## Running the Project

1. Build the project (requires Go 1.19+):
```bash
go build
```

2. Basic usage:
```bash
# Scan a single host
./furious example.com

# Scan specific ports
./furious -p 80,443,8080 example.com

# Use connect scan method
./furious -s connect example.com

# Get JSON output
./furious -j example.com
```

3. Common options:
- `-p, --ports`: Specify ports to scan (default: common ports)
- `-s, --scanner`: Select scan method (connect, syn)
- `-j, --json`: Output results in JSON format
- `-t, --timeout`: Set custom timeout in seconds
- `-h, --help`: Show help message

## System Requirements & OS Version Check

1. Check your OS version:
```bash
# On Linux
cat /etc/os-release
uname -a

# On macOS
sw_vers
uname -a

# On Windows
ver
systeminfo
```

2. Supported Operating Systems:
- Linux (kernel 2.6 or later)
- macOS 10.12+
- Windows 7/10/11

Note: Some scanning features may require root/administrator privileges