# Furious IP/Port Scanner

Furious is a fast, lightweight, portable network scanner.

![Screenshot 1](./screenshot.png)
![Screenshot 2](./screenshot2.png)

I haven't done any proper performance testing, but a SYN scan of a single host, including all known ports (~6000) will typically take in the region of 4 seconds. On the same machine, nmap took 98 seconds and produced exactly the same results.

## Install

You'll need to install libpcap.

- On Linux, install `libpcap` with your package manager
- On OSX, `brew install libpcap`
- On Windows, install [WinPcap](https://www.winpcap.org/)

Then just:

```
go get -u github.com/liamg/furious
```

## Options

### `-s [TYPE]` `--scan-type [TYPE]`

Use the specified scan type. The options are:

| Type       | Description |
|------------|-------------|
| `syn`      | A SYN/stealth scan. Most efficient scan type, using only a partial TCP handshake. Requires root privileges.
| `connect`  | A less detailed scan using full TCP handshakes, though does not require root privileges. 
| `device`   | Attempt to identify device MAC address and manufacturer where possible. Useful for listing devices on a LAN.

The default is a SYN scan.

### `-p [PORTS]` `--ports [PORTS]`

Scan the specified ports. Defaults to a list of all known ports as [provided by IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml).

Ports may be specified using a comma delimited list, and ranges are also allowed.

For example:

```
--ports 22,80,443,8080-8082
```

...will scan 22, 80, 443, 8080, 8081, and 8082.

### `-t [MS]` `--timout-ms [MS]`

The network timeout to apply to each port being checked. Default is *1000ms*.

### `-w [COUNT]` `--workers [COUNT]`

The number of worker routines to use to scan ports in parallel. Default is *1000* workers.

### `-u` `--up-only`

Only show output for hosts that are confirmed as up.

### `--version`

Output version information and exit.

## Usage

Furious can be used to:

### Find open ports on one or more hosts

Scan a single host:
```
furious 192.168.1.4 
```

Scan a whole CIDR:
```
furious 192.168.1.0/24 
```

### Scan a mixture of IPs, hostnames and CIDRs

```
furious -s connect 8.8.8.8 192.168.1.1/24 google.com
```

### Run a SYN (stealth) scan (with root privileges)

```
sudo -E furious -s syn 192.168.1.1
```

### Run a connect scan as any user

```
furious -s connect 192.168.1.1
```

### Identify device MAC address and manufacturer within a local network

```
furious -s device 192.168.1.1/24 -u
```

## Troubleshooting

### `sudo: furious: command not found`

If you installed using go, your user has the environment variables required to locate go programs, but root does not. You need to:

```
sudo env "PATH=$PATH" furious
```

## Library Usage

Furious can be used as a Go library in your own projects:

### Simple Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/liamg/furious/scan"
)

func main() {
    // Quick port check
    portStatus, err := scan.QuickPortCheck("example.com", 80, 443, 22)
    if err != nil {
        log.Fatal(err)
    }
    
    for port, isOpen := range portStatus {
        status := "CLOSED"
        if isOpen {
            status = "OPEN"
        }
        fmt.Printf("Port %d: %s\n", port, status)
    }
    
    // Check if host is up
    isUp, err := scan.IsHostUp("example.com")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Host is up: %v\n", isUp)
}
```

### Advanced Usage

```go
// Custom configuration
config := scan.LibraryConfig{
    TimeoutMS: 5000,  // 5 second timeout
    Workers:   100,   // 100 parallel workers
    ScanType:  "connect",
    Retries:   2,     // 2 retries for reliability
}

scanner, err := scan.NewScannerFromConfig("target.com", config)
if err != nil {
    log.Fatal(err)
}

if err := scanner.Start(); err != nil {
    log.Fatal(err)
}

results, err := scanner.Scan(context.Background(), []int{80, 443, 22})
if err != nil {
    log.Fatal(err)
}

for _, result := range results {
    fmt.Printf("Host: %s, Open ports: %v\n", result.Host, result.Open)
}
```

### Fixed Manual Scanner Usage

If you prefer the manual approach, make sure to use `time.Duration` correctly:

```go
// CORRECT: Use time.Duration for timeout
targetIterator := scan.NewTargetIterator("192.168.3.5")
timeout := time.Duration(6000) * time.Millisecond  // 6 seconds
scanner := scan.NewConnectScanner(targetIterator, timeout, 1000)

// The rest of your code...
```

The issue in your original code was passing `6000` as an integer instead of a proper `time.Duration`. This caused the timeout to be interpreted as 6000 nanoseconds (0.006ms) instead of 6000 milliseconds.

## SYN/Connect scans are slower than nmap!

They're not in my experience, but with default arguments furious scans nearly six times as many ports as nmap does by default.
