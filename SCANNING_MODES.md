# Furious Scanning Modes

## SYN Scan (Half-Open / Stealth Scan)

The SYN scan (`-s syn` or `-s stealth`) implements **true half-open scanning**:

### How it Works:
1. **Sends SYN packet** to target port
2. **Waits for response**:
   - SYN-ACK = Port is OPEN
   - RST = Port is CLOSED  
   - No response = Port is FILTERED
3. **Never completes handshake** (no ACK sent back)
4. **Stealthy** - harder to detect than full connections

### Requirements:
- **Root/Administrator privileges** (for raw socket access)
- **libpcap/WinPcap** installed
- **Network interface access**

### Example:
```bash
# Linux/Mac (requires sudo)
sudo ./furious -s syn 192.168.1.1

# Windows (run as Administrator)  
furious.exe -s syn 192.168.1.1
```

### Technical Implementation:
- Uses `google/gopacket` for packet crafting
- Raw socket operations via pcap
- Custom TCP packet construction
- Packet capture and analysis

## Connect Scan (Full TCP Connection)

The connect scan (`-s connect`) uses full TCP connections:

### How it Works:
1. **Establishes full TCP connection** using `net.DialTimeout()`
2. **Immediately closes connection**
3. **Easier to detect** but works without privileges

### Requirements:
- **No special privileges** needed
- **Standard network access**

### Example:
```bash
# Works for any user
./furious -s connect 192.168.1.1
```

## Performance Comparison

| Scan Type | Speed | Stealth | Privileges | Detection Risk |
|-----------|-------|---------|------------|----------------|
| SYN       | Fast  | High    | Required   | Low           |
| Connect   | Slower| Low     | None       | High          |

## Recommendation

- **Use SYN scan** for stealth and performance (when you have privileges)
- **Use Connect scan** for compatibility (when you don't have privileges)