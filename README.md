# DPI Engine - Java Implementation

A **Deep Packet Inspection (DPI) Engine** written in Java for analyzing, classifying, and filtering network traffic. It reads PCAP files, identifies application protocols (YouTube, Facebook, DNS, etc.), and can apply blocking rules based on domains or applications.

---

## Table of Contents

1. [Features](#features)
2. [Project Structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Setup & Installation](#setup--installation)
5. [Build Instructions](#build-instructions)
6. [Running the Engine](#running-the-engine)
7. [Single-Threaded Usage](#single-threaded-usage)
8. [Multi-Threaded Usage](#multi-threaded-usage)
9. [Blocking Rules](#blocking-rules)
10. [Output](#output)
11. [Troubleshooting](#troubleshooting)

---

## Features

✅ **PCAP File Processing** - Read and parse network packets from PCAP files
✅ **Protocol Detection** - Identify TCP, UDP, DNS, HTTP, HTTPS (TLS)
✅ **Application Classification** - Detect YouTube, Facebook, Google, Netflix, Twitter, Discord, etc.
✅ **SNI Extraction** - Extract Server Name Indication from TLS handshakes
✅ **Domain Detection** - Identify domains from HTTP Host headers and DNS queries
✅ **Traffic Filtering** - Block traffic by application or domain
✅ **Statistics Reporting** - Detailed packet and byte statistics
✅ **Multi-Protocol Support** - IPv4, TCP, UDP, DNS, HTTP
✅ **Multi-Threaded Processing** - Parallel packet processing with load balancing
✅ **Configurable Thread Pool** - Custom worker thread count

---

## Project Structure

```
src/main/java/com/dpi/
├── engine/
│   ├── DPIEngine.java              # Single-threaded processing engine
│   ├── MultiThreadedDPIEngine.java # Multi-threaded processing engine
│   ├── LoadBalancerThread.java     # Distributes packets to workers
│   ├── FastPathThread.java         # Worker thread for packet processing
│   └── RuleManager.java            # Rule management for blocking
├── parser/
│   ├── PacketParser.java        # Packet parsing (Ethernet, IP, TCP, UDP)
│   └── ParsedPacket.java        # Parsed packet data structure
├── extractor/
│   ├── SNIExtractor.java        # Extract SNI from TLS ClientHello
│   ├── HTTPHostExtractor.java   # Extract Host header from HTTP
│   └── DNSExtractor.java        # Extract domain from DNS queries
├── pcap/
│   ├── PcapReader.java          # Read PCAP files
│   └── RawPacket.java           # Raw packet data structure
├── types/
│   ├── FiveTuple.java           # Flow identifier (srcIP, dstIP, srcPort, dstPort, proto)
│   ├── Connection.java          # Connection state tracking
│   ├── ConnectionState.java     # Connection state enum
│   ├── AppType.java             # Application type enum
│   ├── PacketAction.java        # Action enum (FORWARD/DROP)
│   └── DPIStats.java            # Statistics tracking
└── threading/
    └── ThreadSafeQueue.java     # Thread-safe queue for multi-threading

pom.xml                          # Maven configuration
```

---

## Prerequisites

- **Java 11+** (tested with JDK 21)
- **Maven 3.6+** (optional, for Maven builds)
- **PCAP file** (for testing)

### Check Java Version

```powershell
java -version
```

Expected output:
```
java version "21.0.x" ...
```

---

## Setup & Installation

### Option 1: Using Maven (Recommended)

1. **Navigate to project directory:**
```powershell
cd C:\Users\Sahil\Packet_analyzer\src
```

2. **Build with Maven:**
```powershell
mvn clean package
```

3. **Run from JAR:**
```powershell
java -jar target/dpi-engine-1.0.jar test_dpi.pcap output.pcap
```

### Option 2: Manual Compilation (No Maven)

1. **Navigate to Java source directory:**
```powershell
cd C:\Users\Sahil\Packet_analyzer
```

2. **Create output directory:**
```powershell
mkdir -p bin
```

3. **Compile all Java files:**
```powershell
javac -d bin -cp src\main\java `
  src\main\java\com\dpi\types\*.java `
  src\main\java\com\dpi\parser\*.java `
  src\main\java\com\dpi\extractor\*.java `
  src\main\java\com\dpi\pcap\*.java `
  src\main\java\com\dpi\threading\*.java `
  src\main\java\com\dpi\engine\*.java
```

---

## Build Instructions

### Full Compilation (One Command)

```powershell
cd C:\Users\Sahil\Packet_analyzer

javac -d bin -cp src\main\java `
  src\main\java\com\dpi\types\*.java `
  src\main\java\com\dpi\parser\*.java `
  src\main\java\com\dpi\extractor\*.java `
  src\main\java\com\dpi\pcap\*.java `
  src\main\java\com\dpi\threading\*.java `
  src\main\java\com\dpi\engine\*.java
```

### Verify Compilation

```powershell
dir bin\com\dpi\engine
```

You should see `DPIEngine.class` and `RuleManager.class`

### Quick Recompile (After Changes)

If you only modified the engine:
```powershell
javac -d bin -cp src\main\java src\main\java\com\dpi\engine\*.java
```

---

## Running the Engine

### Generate Test PCAP (If Needed)

```powershell
cd C:\Users\Sahil\Packet_analyzer
python generate_test_pcap.py
```

This creates `test_dpi.pcap` with:
- 16 TLS connections with SNI
- 2 HTTP connections
- 4 DNS queries
- 5 packets from blocked IP

---

## Single-Threaded Usage

### Basic Syntax

```powershell
java -cp bin com.dpi.engine.DPIEngine <input.pcap> <output.pcap> [options]
```

### 1. **Basic Processing** (No Filtering)

```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap
```

**Output:**
```
Opened PCAP file: test_dpi.pcap
  Version: 2.4
  Snaplen: 65535 bytes
Starting DPI processing...

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ Total Bytes:                  5738                           ║
║ TCP Packets:                  73                             ║
║ UDP Packets:                  4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    77                             ║
║ Dropped:                      0                              ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - www.netflix.com -> Netflix
  - discord.com -> Discord
```

### 2. **Block Specific Application**

```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap --block-app YouTube
```

**Output:**
```
[Rules] Blocked app: YouTube
Opened PCAP file: test_dpi.pcap
  ...
║ Forwarded:                    75                             ║
║ Dropped:                      2                              ║
```

### 3. **Block Specific Domain**

```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap --block-domain facebook.com
```

### 4. **Block Multiple Applications**

```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap `
  --block-app YouTube `
  --block-app Facebook `
  --block-app Netflix
```

### 5. **Block Multiple Domains**

```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap `
  --block-domain facebook.com `
  --block-domain youtube.com
```

### 6. **Combined Blocking (Apps + Domains)**

```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap `
  --block-app YouTube `
  --block-domain facebook.com `
  --block-app Netflix
```

---

## Multi-Threaded Usage

**The multi-threaded engine provides parallel packet processing using worker threads and load balancing.**

### Basic Syntax

```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine <input.pcap> <output.pcap> [options]
```

### Multi-Threaded Examples

### 1. **Default (Auto-Detect CPU Cores)**

```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap
```

**Output:**
```
Opened PCAP file: test_dpi.pcap
  Version: 2.4
  Snaplen: 65535 bytes
Starting Multi-Threaded DPI Processing with 12 worker threads...
All packets queued (77). Waiting for processing...

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ Total Bytes:                  5738                           ║
║ TCP Packets:                  73                             ║
║ UDP Packets:                  4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    77                             ║
║ Dropped:                      0                              ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - ...
DPI processing completed successfully
```

### 2. **Custom Thread Count**

```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap --threads 4
```

**Use `--threads N` to specify worker thread count:**
- `--threads 2` - 2 worker threads (for low-resource environments)
- `--threads 4` - 4 worker threads (balanced)
- `--threads 8` - 8 worker threads (high-performance)

### 3. **Multi-Threaded with Blocking**

```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap `
  --threads 4 `
  --block-app YouTube
```

**Output:**
```
[Rules] Blocked app: YouTube
Opened PCAP file: test_dpi.pcap
  ...
Starting Multi-Threaded DPI Processing with 4 worker threads...
All packets queued (77). Waiting for processing...

║ Forwarded:                    75                             ║
║ Dropped:                      2                              ║
```

### 4. **Multi-Threaded Block Multiple Apps**

```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap `
  --threads 8 `
  --block-app YouTube `
  --block-app Facebook `
  --block-app Netflix
```

### 5. **Multi-Threaded Block by Domain**

```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap `
  --threads 4 `
  --block-domain facebook.com `
  --block-domain youtube.com
```

### 6. **Multi-Threaded Combined Blocking**

```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap `
  --threads 6 `
  --block-app YouTube `
  --block-domain facebook.com `
  --block-app Netflix
```

### Performance Comparison

| Engine | Threads | Best For | Latency | Throughput |
|--------|---------|----------|---------|------------|
| Single-threaded | 1 | Small PCAP files | Low | Low |
| Multi-threaded | Auto (CPU cores) | Large PCAP files | High | **Very High** |
| Multi-threaded | 4 | Balanced | Medium | High |
| Multi-threaded | 8+ | High-performance | Low | **Highest** |

**Recommended settings:**
- Small files (<1MB): Use single-threaded DPIEngine
- Medium files (1-100MB): Use MultiThreadedDPIEngine with `--threads 4`
- Large files (>100MB): Use MultiThreadedDPIEngine with `--threads 8` or more

---

## Blocking Rules

### Supported Applications

| App | Identifier |
|-----|-----------|
| YouTube | `--block-app YouTube` |
| Facebook | `--block-app Facebook` |
| Google | `--block-app Google` |
| Netflix | `--block-app Netflix` |
| Amazon | `--block-app Amazon` |
| Microsoft | `--block-app Microsoft` |
| Apple | `--block-app Apple` |
| WhatsApp | `--block-app WhatsApp` |
| Telegram | `--block-app Telegram` |
| TikTok | `--block-app TikTok` |
| Spotify | `--block-app Spotify` |
| Zoom | `--block-app Zoom` |
| Discord | `--block-app Discord` |
| GitHub | `--block-app GitHub` |
| Cloudflare | `--block-app Cloudflare` |
| Twitter | `--block-app Twitter` |
| Instagram | `--block-app Instagram` |

### Domain Blocking

Block any domain by name:
```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap --block-domain example.com
```

---

## Output

### Screen Output

1. **PCAP Information**
   - File version
   - Snapshot length (max packet size)

2. **Processing Report**
   - Total packets and bytes processed
   - TCP/UDP packet breakdown
   - Forwarded vs Dropped count

3. **Detected Domains/SNIs**
   - Unique domains found
   - Application classification
   - Sorted alphabetically

### Output PCAP File

The `output.pcap` file contains:
- All **forwarded** packets (not blocked)
- Can be opened in **Wireshark** for further analysis
- File format: Standard PCAP

**View output file:**
```powershell
(Get-ChildItem output.pcap).Length
# Shows file size in bytes
```

**Open in Wireshark:**
```powershell
wireshark output.pcap
```

---

## Troubleshooting

### Error: "Could not find or load main class"

**Cause:** Java files not compiled or wrong classpath

**Fix:**
```powershell
# Recompile all files
javac -d bin -cp src\main\java `
  src\main\java\com\dpi\types\*.java `
  src\main\java\com\dpi\parser\*.java `
  src\main\java\com\dpi\extractor\*.java `
  src\main\java\com\dpi\pcap\*.java `
  src\main\java\com\dpi\threading\*.java `
  src\main\java\com\dpi\engine\*.java
```

### Error: "Cannot find file test_dpi.pcap"

**Cause:** PCAP file doesn't exist

**Fix:**
```powershell
cd C:\Users\Sahil\Packet_analyzer
python generate_test_pcap.py
```

### Error: "Usage: java DPIEngine <input.pcap> <output.pcap>"

**Cause:** Missing command-line arguments

**Fix:** Provide both input and output files:
```powershell
java -cp bin com.dpi.engine.DPIEngine input.pcap output.pcap
```

### Output shows "TCP Packets: 0"

**Cause:** Packet parsing not working correctly

**Fix:** Verify the PCAP file is valid:
```powershell
file test_dpi.pcap
```

Should output: `test_dpi.pcap: pcap capture file - version 2.4`

### No Domains Detected

**Cause:** PCAP file may not contain TLS/HTTP/DNS traffic

**Fix:** Generate new test PCAP or use real network capture from Wireshark

---

## Architecture

### Data Flow

```
Input PCAP File
        ↓
   PcapReader (reads raw packets)
        ↓
   PacketParser (extracts headers)
        ├─ Ethernet header
        ├─ IPv4 header
        ├─ TCP/UDP header
        └─ Payload
        ↓
   Extractors (identify applications)
        ├─ SNIExtractor (TLS)
        ├─ HTTPHostExtractor (HTTP)
        └─ DNSExtractor (DNS)
        ↓
   RuleManager (apply blocking rules)
        ↓
   Output PCAP File + Report
```

### Multi-Threaded Architecture

```
Input PCAP (Main Thread)
        ↓
   PcapReader
        ↓
  Input Queue
        ↓
 LoadBalancerThread (Round-Robin)
   /    |    |    \
  ↓     ↓    ↓     ↓
Worker Queues (FastPathThread x N)
  ↓     ↓    ↓     ↓
Process Packets (Parallel)
  ↓     ↓    ↓     ↓
DPIStats (Thread-Safe)
   \    |    |    /
        ↓
   Output Report
```

**Thread Model:**
- **Main Thread:** Reads PCAP, queues packets
- **LoadBalancerThread:** Distributes packets round-robin to workers
- **FastPathThread (x N):** Parallel packet processing (one per core)
- **Thread Safety:** AtomicLong for statistics, ConcurrentHashMap for flows

### Key Classes

| Class | Purpose |
|-------|---------|
| `DPIEngine` | Single-threaded processing loop |
| `MultiThreadedDPIEngine` | Multi-threaded processing orchestrator |
| `LoadBalancerThread` | Distributes packets to worker queues |
| `FastPathThread` | Worker thread for parallel processing |
| `PcapReader` | Reads PCAP file format |
| `PacketParser` | Parses Ethernet, IP, TCP, UDP headers |
| `SNIExtractor` | Extracts domain from TLS ClientHello |
| `HTTPHostExtractor` | Extracts Host header from HTTP requests |
| `DNSExtractor` | Extracts domain from DNS queries |
| `RuleManager` | Manages and applies blocking rules |
| `Connection` | Tracks state for each flow |
| `DPIStats` | Thread-safe statistics collection (AtomicLong) |

---

## Common Use Cases

### **Single-Threaded (Small Files)**

### 1. **Monitor All Network Traffic**
```powershell
java -cp bin com.dpi.engine.DPIEngine capture.pcap report.pcap
```

### 2. **Block YouTube Only**
```powershell
java -cp bin com.dpi.engine.DPIEngine capture.pcap filtered.pcap --block-app YouTube
```

### 3. **Block Social Media**
```powershell
java -cp bin com.dpi.engine.DPIEngine capture.pcap filtered.pcap `
  --block-app Facebook --block-app Instagram --block-app TikTok
```

### **Multi-Threaded (Large Files - FASTER)**

### 4. **High-Performance Monitoring**
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine capture.pcap report.pcap --threads 8
```

### 5. **Parallel Processing with Blocking**
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine large_capture.pcap filtered.pcap `
  --threads 8 `
  --block-app YouTube `
  --block-app Netflix
```

### 6. **Block Streaming Services (Parallel)**
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine capture.pcap filtered.pcap `
  --threads 4 `
  --block-app Netflix --block-app YouTube --block-app Spotify
```

### 7. **Block by Domain (Parallel)**
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine capture.pcap filtered.pcap `
  --threads 6 `
  --block-domain ads.example.com --block-domain tracker.example.com
```

---

## Performance Tips

### Single-Threaded
- **Classpath:** Use `-cp bin` for faster startup than full path
- **Input File:** Best for files <1MB
- **Multiple Blocks:** Blocking multiple apps doesn't significantly impact performance

### Multi-Threaded
- **Auto Thread Detection:** Default uses `Runtime.getRuntime().availableProcessors()`
- **Custom Threads:** Use `--threads N` to override (e.g., `--threads 4` for 4 workers)
- **Load Balancing:** Round-robin distribution across workers (no packet ordering guaranteed in output)
- **Thread Overhead:** Minimal overhead with 4+ threads; optimal at 4-8 threads
- **Memory:** Each thread gets its own queue; monitor memory for very large thread counts
- **Blocking Rules:** Equally efficient in multi-threaded version (thread-safe updates)

---

## Wireshark - Inspecting Output PCAP Files

### What is Wireshark?

**Wireshark** is a free, open-source network packet analyzer that lets you see what's happening on your network in real-time. It reads PCAP files and displays:
- **Packet List** - All packets with timestamps, source/dest IPs, protocols
- **Packet Details** - Full packet headers broken down (Ethernet, IP, TCP, UDP, DNS, HTTP, TLS)
- **Packet Bytes** - Raw hexadecimal view of packet data
- **Statistics** - Protocol breakdowns, conversation flows, packet counts

### Download Wireshark

**Windows:**
```powershell
# Download from official website
https://www.wireshark.org/download/

# Or use Chocolatey:
choco install wireshark
```

**Verify Installation:**
```powershell
wireshark --version
```

### Opening Output PCAP Files

#### Method 1: Command Line
```powershell
# Open output file in Wireshark
wireshark output.pcap

# Open multi-threaded output
wireshark output_mt.pcap
```

#### Method 2: GUI
1. Open Wireshark application
2. **File** → **Open** (or Ctrl+O)
3. Navigate to `C:\Users\Sahil\Packet_analyzer\`
4. Select `output.pcap` or `output_mt.pcap`
5. Click **Open**

### What to Look For in Wireshark

#### 1. **Packet List (Top Panel)**
Shows all packets with:
- **No.** - Packet number
- **Time** - Timestamp
- **Source** - Source IP address
- **Destination** - Destination IP address
- **Protocol** - TCP, UDP, DNS, TLS, HTTP, etc.
- **Length** - Packet size in bytes
- **Info** - Protocol-specific details

**Example:**
```
No.  Time        Source      Destination  Protocol  Length  Info
1    0.000000    192.168.1.1 8.8.8.8       TCP       66      [SYN]
2    0.001234    8.8.8.8     192.168.1.1   TCP       66      [SYN, ACK]
3    0.002456    192.168.1.1 8.8.8.8       TLS       517     Client Hello
```

#### 2. **Packet Details (Middle Panel)**
Expand tree items to see:
- **Frame** - Frame metadata, timestamps
- **Ethernet II** - MAC addresses
- **Internet Protocol Version 4** - Source/dest IP, TTL, flags
- **Transmission Control Protocol** - Source/dest ports, flags, sequence numbers
- **Transport Layer Security** - TLS record type, version, handshake info
  - **TLS Handshake** → **Server Name Indication (SNI)** - Shows domain!

**Example - Finding SNI:**
```
Frame 3: 517 bytes
  Ethernet II: 00:11:22:33:44:55 → aa:bb:cc:dd:ee:ff
  Internet Protocol Version 4: 192.168.1.1 → 8.8.8.8
  Transmission Control Protocol: 443 (HTTPS/TLS)
  TLS Record Layer: Handshake Protocol: Client Hello
    Handshake Protocol: Client Hello
      Extensions (51 bytes)
        server_name [length=19]
          Server Name: www.youtube.com  ← DOMAIN DETECTED!
```

#### 3. **Packet Bytes (Bottom Panel)**
Raw hexadecimal data of the packet. Useful for debugging binary protocol details.

### Key Filters in Wireshark

#### 1. **Filter Specific Protocol**
```
# Show only TLS packets
tls

# Show only TCP packets
tcp

# Show only DNS packets
dns

# Show only HTTP packets
http
```

#### 2. **Filter by IP**
```
# Show traffic from specific IP
ip.src == 192.168.1.1

# Show traffic to specific IP
ip.dst == 8.8.8.8

# Show traffic between two IPs
ip.src == 192.168.1.1 && ip.dst == 8.8.8.8
```

#### 3. **Filter by Port**
```
# Show HTTPS traffic (port 443)
tcp.port == 443

# Show DNS traffic (port 53)
udp.port == 53

# Show HTTP traffic (port 80)
tcp.port == 80
```

#### 4. **Filter by Domain (SNI)**
```
# Show TLS packets with specific domain
tls.handshake.extensions_server_name == "youtube.com"

# Show all HTTPS traffic (contains TLS)
tls
```

#### 5. **Complex Filters**
```
# TLS traffic from specific IP
tcp.port == 443 && ip.src == 192.168.1.1

# DNS or HTTPS traffic
dns || tls

# All traffic except localhost
ip.src != 127.0.0.1 && ip.dst != 127.0.0.1
```

### Comparing Output Files

To compare single-threaded vs multi-threaded output:

```powershell
# Terminal 1: Open single-threaded output
wireshark output.pcap

# Terminal 2: Open multi-threaded output
wireshark output_mt.pcap

# Compare in side-by-side windows
```

**Both should contain the same packets** (though multi-threaded order may differ due to load balancing)

### Example Workflow

#### Step 1: Run DPI Engine
```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap --block-app YouTube
```

#### Step 2: Open Output in Wireshark
```powershell
wireshark output.pcap
```

#### Step 3: Apply Filter
```
# In Wireshark Filter box, type:
tls

# Press Enter to filter
```

#### Step 4: Inspect SNI
- Click on any TLS packet
- Expand **Transmission Control Protocol**
- Expand **Transport Layer Security**
- Expand **Handshake Protocol: Client Hello**
- Expand **Extensions**
- Expand **server_name** to see the domain

#### Step 5: Verify Blocking
- YouTube packets should be missing (dropped)
- Other domains should be present (forwarded)
- Compare with unfiltered output to verify differences

### Statistics in Wireshark

#### Protocol Hierarchy
**Statistics** → **Protocol Hierarchy**
Shows:
- Packet count per protocol
- Byte count per protocol
- Percentage of total traffic

```
Frame                   77 packets    5738 bytes
  Ethernet             77 packets    5738 bytes
    IPv4               77 packets    5738 bytes
      TCP              73 packets    5205 bytes
        TLS            19 packets    2841 bytes
        HTTP            2 packets     412 bytes
      UDP               4 packets     533 bytes
        DNS             4 packets     533 bytes
```

#### Conversations
**Statistics** → **Conversations**
Shows:
- IP conversations (src ↔ dest)
- TCP/UDP streams
- Packet count and bytes per conversation
- Direction (A→B, B→A, both)

### Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| "No packets found" | File might be empty; verify PCAP wasn't deleted |
| "Can't open file" | Check file path, ensure file exists |
| "Invalid PCAP format" | File corrupted; regenerate with `python generate_test_pcap.py` |
| "Filter syntax error" | Use Display Filters (not Capture Filters); reload file if changed |
| "Slow startup" | Large PCAP files take time to load; be patient or use filters |

### Tips & Tricks

1. **Color Coding:** Wireshark colors packets by protocol for quick scanning
2. **Follow TCP Stream:** Right-click packet → **Follow** → **TCP Stream** to see full conversation
3. **Export Packets:** **File** → **Export Specified Packets** to create subset PCAP
4. **Search:** Edit → **Find Packet** to search by text/hex
5. **Bookmarks:** Click packet → right-click → **Mark/Unmark Packet** to bookmark interesting packets
6. **Resolve Names:** **View** → **Name Resolution** to show hostnames (requires DNS setup)

---

## File I/O

### Input PCAP Format
- Standard PCAP file format (tcpdump compatible)
- Can be created with:
  - Wireshark (GUI)
  - tcpdump (command-line)
  - Python (scapy)
  - Built-in `generate_test_pcap.py`

### Output PCAP Format
- Standard PCAP file format
- Contains **filtered packets** based on blocking rules
- Compatible with Wireshark, tcpdump, etc.
- **Useful for:** Verifying which packets were forwarded vs dropped

---

## Quick Start Guide

### Step 1: Generate Test Data
```powershell
cd C:\Users\Sahil\Packet_analyzer
python generate_test_pcap.py
```

### Step 2: Compile All Java Files
```powershell
javac -d bin -cp src\main\java `
  src\main\java\com\dpi\types\*.java `
  src\main\java\com\dpi\parser\*.java `
  src\main\java\com\dpi\extractor\*.java `
  src\main\java\com\dpi\pcap\*.java `
  src\main\java\com\dpi\threading\*.java `
  src\main\java\com\dpi\engine\*.java
```

### Step 3: Run Single-Threaded Test
```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap
```

### Step 4: Run Multi-Threaded Test
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap --threads 4
```

### Step 5: Test with Blocking Rules
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap `
  --threads 4 `
  --block-app YouTube `
  --block-domain facebook.com
```

### Step 6: Inspect Output
```powershell
wireshark output.pcap
wireshark output_mt.pcap
```

---

## License

This project is part of the Packet Analyzer suite.