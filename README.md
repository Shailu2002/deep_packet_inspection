# DPI Engine - Deep Packet Inspection System

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Classification + Report
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Applies blocking rules (IP / App / Domain)
                    - Generates a per-run report
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
+-----------------------------------------------------------+
| Layer 7: Application    | HTTP, TLS, DNS                  |
+-----------------------------------------------------------+
| Layer 4: Transport      | TCP (reliable), UDP (fast)      |
+-----------------------------------------------------------+
| Layer 3: Network        | IP addresses (routing)          |
+-----------------------------------------------------------+
| Layer 2: Data Link      | MAC addresses (local network)   |
+-----------------------------------------------------------+
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
+----------------------------------------------------------------+
| Ethernet Header (14 bytes)                                     |
|  +--------------------------------------------------------+    |
|  | IP Header (20 bytes)                                    |    |
|  |  +----------------------------------------------------+ |    |
|  |  | TCP/UDP Header (20 / 8 bytes)                       | |    |
|  |  |  +------------------------------------------------+ | |    |
|  |  |  | Payload (Application Data)                      | | |    |
|  |  |  | e.g., TLS Client Hello with SNI                 | | |    |
|  |  |  +------------------------------------------------+ | |    |
|  |  +----------------------------------------------------+ |    |
|  +--------------------------------------------------------+    |
+----------------------------------------------------------------+
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers
- In this project it's also the **hash key used for multi-thread routing** (Section 6)

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
+-- Version: TLS 1.2
+-- Random: [32 bytes]
+-- Cipher Suites: [list]
+-- Extensions:
    +-- SNI Extension:
        +-- Server Name: "www.youtube.com"  <- We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

### Network Byte Order

Network protocols use **big-endian** byte order (most significant byte first), which may differ from your machine's native order. This project uses `ByteBuffer` with an explicit order to handle that:

```java
ByteBuffer bb = ByteBuffer.wrap(data, offset, 2);
bb.order(ByteOrder.BIG_ENDIAN);   // network byte order
int port = bb.getShort() & 0xFFFF;
```

---

## 3. Project Overview

### What This Project Does

```
+-------------+     +-------------+     +-------------+
| Wireshark   |     | DPI Engine  |     | Console     |
| Capture     | --> | (Java)      | --> | Report      |
| (input.pcap)|     | - Parse     |     | (stats +    |
+-------------+     | - Classify  |     |  detected   |
                    | - Block     |     |  domains)   |
                    +-------------+     +-------------+
```

### Two Versions

| Version | Class | Use Case |
|---------|-------|----------|
| Simple (Single-threaded) | `com.dpi.engine.DPIEngine` | Learning, small captures |
| Multi-threaded (2-tier hierarchical) | `com.dpi.engine.MultiThreadedDPIEngine` | Production, large captures |

---

## 4. File Structure

```
src/main/java/com/dpi/
+-- engine/
|   +-- DPIEngine.java              # Single-threaded processing engine
|   +-- MultiThreadedDPIEngine.java # Multi-threaded orchestrator (2-tier hierarchy)
|   +-- LoadBalancerThread.java     # Tier-1: hash-routes packets to its own workers
|   +-- FastPathThread.java         # Tier-2 worker: classification + rules + stats
|   +-- RuleManager.java            # Blocking rules (IP / App / Domain)
+-- parser/
|   +-- PacketParser.java           # Packet parsing (Ethernet, IP, TCP, UDP)
|   +-- ParsedPacket.java           # Parsed packet data structure
+-- extractor/
|   +-- SNIExtractor.java           # Extract SNI from TLS ClientHello
|   +-- HTTPHostExtractor.java      # Extract Host header from HTTP
|   +-- DNSExtractor.java           # Extract domain from DNS queries
+-- pcap/
|   +-- PcapReader.java             # Read PCAP files
|   +-- RawPacket.java              # Raw packet data structure
+-- types/
|   +-- FiveTuple.java              # Flow identifier (srcIP, dstIP, srcPort, dstPort, proto)
|   +-- Connection.java             # Connection state tracking
|   +-- ConnectionState.java        # Connection state enum
|   +-- AppType.java                # Application type enum
|   +-- PacketAction.java           # Action enum (FORWARD/DROP/INSPECT/LOG_ONLY)
|   +-- DPIStats.java               # Thread-safe statistics (AtomicLong)
+-- threading/
    +-- ThreadSafeQueue.java        # Generic BlockingQueue wrapper
    +-- RoutedPacket.java           # Carries raw+parsed packet, FiveTuple & routing hash between tiers

test_dpi.pcap                       # Sample capture with various traffic
generate_test_pcap.py               # Creates test data
README.md                           # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `DPIEngine.java`:

### Step 1: Read PCAP File

```java
PcapReader reader = new PcapReader();
reader.open("capture.pcap");
```

**What happens:**
1. Open the file with `RandomAccessFile`
2. Read the 24-byte global header (magic number, version, snaplen, etc.)
3. Check the magic number to detect endianness, and reject the file if it isn't a valid PCAP

**PCAP File Format:**
```
+----------------------------+
| Global Header (24 bytes)   |  <- Read once at start
+----------------------------+
| Packet Header (16 bytes)   |  <- Timestamp, length
| Packet Data (variable)     |  <- Actual network bytes
+----------------------------+
| Packet Header (16 bytes)   |
| Packet Data (variable)     |
+----------------------------+
| ... more packets ...       |
+----------------------------+
```

### Step 2: Read Each Packet

```java
RawPacket rawPacket = new RawPacket();
while (pcapReader.readNextPacket(rawPacket)) {
    // rawPacket.data contains the packet bytes
    // rawPacket.header contains timestamp and length
}
```

**What happens:**
1. Read the 16-byte packet header
2. Allocate a `byte[]` of length `header.inclLen` and read the packet data into it
3. `readNextPacket()` returns `false` when there's nothing left to read

### Step 3: Parse Protocol Headers

```java
ParsedPacket parsed = new ParsedPacket();
PacketParser.parse(rawPacket, parsed);
```

**What happens (in `PacketParser.java`):**

```
rawPacket.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header (or [34-41] for UDP)
[54+]    Payload

After parsing:
parsed.srcMac    = "00:11:22:33:44:55"
parsed.destMac   = "aa:bb:cc:dd:ee:ff"
parsed.srcIp     = "192.168.1.100"
parsed.destIp    = "172.217.14.206"
parsed.srcPort   = 54321
parsed.destPort  = 443
parsed.protocol  = 6 (TCP)
parsed.hasTCP    = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```
```java
private static boolean parseEthernet(byte[] data, ParsedPacket parsed, int offset) {
    parsed.destMac = macToString(data, offset);
    parsed.srcMac  = macToString(data, offset + 6);
    ByteBuffer bb = ByteBuffer.wrap(data, offset + 12, 2);
    bb.order(ByteOrder.BIG_ENDIAN);
    parsed.etherType = bb.getShort() & 0xFFFF;
    return true;
}
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length / IHL (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```
The header length isn't fixed - it's `IHL * 4` bytes, so the offset to the next layer is computed, not hardcoded:
```java
int versionIHL = data[offset] & 0xFF;
int ihl = (versionIHL & 0x0F) * 4;
offset += ihl;
```

**Parsing the TCP Header (20+ bytes, variable):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (top 4 bits = header length in 32-bit words)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```
Same idea - TCP header length is variable too:
```java
int dataOffset = (data[offset + 12] & 0xFF) >> 4;
int tcpHeaderLen = dataOffset * 4;
offset += tcpHeaderLen;
```
UDP is simpler - its header is always exactly 8 bytes, so no length calculation is needed.

### Step 4: Create Five-Tuple and Look Up Flow

```java
FiveTuple tuple = new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);
Connection connection = flows.computeIfAbsent(tuple, t -> new Connection(t));
```

**What happens:**
- `flows` is a `Map<FiveTuple, Connection>` (a `ConcurrentHashMap` even in the single-threaded engine)
- `FiveTuple` overrides `equals()`/`hashCode()` (via `Objects.hash(...)`) so two tuples with the same 5 values are treated as the same map key
- `computeIfAbsent` returns the existing `Connection` if this flow has been seen before, or creates a new one

### Step 5: Extract SNI (Deep Packet Inspection)

```java
if (parsed.destPort == 443 && parsed.payloadLength > 5) {
    Optional<String> sni = SNIExtractor.extract(parsed.payloadData, 0, parsed.payloadLength);
    if (sni.isPresent()) {
        connection.setSni(sni.get());                      // "www.youtube.com"
        connection.setAppType(AppType.fromSni(sni.get()));  // AppType.YOUTUBE
        connection.setState(ConnectionState.CLASSIFIED);
    }
}
```

**What happens (in `SNIExtractor.java`):** see [Section 8](#8-how-sni-extraction-works) for the full byte-by-byte walkthrough. Short version:
1. Check the TLS record is a Client Hello (`payload[0] == 0x16`, `payload[5] == 0x01`)
2. Skip over Version, Random, Session ID, Cipher Suites, Compression Methods
3. Walk the Extensions list looking for extension type `0x0000` (SNI)
4. Read the hostname string out of that extension

### Step 6: Check Blocking Rules

```java
if (ruleManager.isBlocked(tuple.getSrcIp(), connection.getAppType(), connection.getSni())) {
    connection.setAction(PacketAction.DROP);
    stats.incDroppedPackets();
} else {
    connection.setAction(PacketAction.FORWARD);
    stats.incForwardedPackets();
}
```

**What happens (in `RuleManager.java`):**
```java
public boolean isBlocked(long srcIp, AppType appType, String sni) {
    if (blockedIPs.contains(srcIp)) return true;
    if (blockedApps.contains(appType)) return true;
    String lowerSni = sni.toLowerCase();
    for (String domain : blockedDomains) {
        if (lowerSni.contains(domain)) return true;   // substring match
    }
    return false;
}
```

### Step 7: Update Stats (No Output File Written Yet)

```java
connection.incPacketsIn();
connection.addBytesIn(rawPacket.data.length);
```

> **Note:** `DPIEngine`/`MultiThreadedDPIEngine` take an `outputFile` argument, but no `PcapWriter` has been built yet - blocking only affects the in-memory `Forwarded`/`Dropped` counters and the connection's `PacketAction`; no filtered `.pcap` file is written to disk yet. This is a known, honest gap - see [Section 12](#12-extending-the-project) for how to close it.

### Step 8: Generate Report

After processing all packets:
```java
flows.values().stream()
    .filter(c -> !c.getSni().isEmpty())
    .sorted(Comparator.comparing(Connection::getSni))
    .distinct()
    .forEach(c -> System.out.printf("  - %s -> %s%n", c.getSni(),
        AppType.toDisplayString(c.getAppType())));
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`MultiThreadedDPIEngine.java`) adds **parallelism** using a **2-tier hierarchical thread architecture**: 2 load balancer threads (`LB-0`, `LB-1`), each owning its own dedicated slice of worker threads (`Worker-0`..`Worker-N`), built with Java's `BlockingQueue`/`ExecutorService`.

### Architecture Overview

```
                    +------------------+
                    |  Reader Thread   |
                    | (reads + parses  |
                    |  PCAP, builds    |
                    |  FiveTuple+hash) |
                    +--------+---------+
                             |
              +--------------+--------------+
              |   Tier-1: hash % 2          |
              v                             v
    +-----------------+           +-----------------+
    |   LB-0 Thread   |           |   LB-1 Thread   |
    | (LoadBalancer)  |           | (LoadBalancer)  |
    +--------+--------+           +--------+--------+
             |                             |
   Tier-2: (hash/2) % workersPerLb   Tier-2: (hash/2) % workersPerLb
      +------+------+               +------+------+
      v             v               v             v
+----------+ +----------+   +----------+ +----------+
| Worker-0 | | Worker-1 |   | Worker-2 | | Worker-3 |
|(FastPath)| |(FastPath)|   |(FastPath)| |(FastPath)|
+-----+----+ +-----+----+   +-----+----+ +-----+----+
      |            |              |            |
      +------------+--------------+------------+
                          |
                          v
      Shared state: ConcurrentHashMap<FiveTuple,Connection>
                     + DPIStats (AtomicLong)
                          |
                          v
                    Output Report
```

### Why This Design?

1. **Load Balancers (LBs):** each owns a fixed slice of workers - no single dispatcher is a bottleneck for the whole system
2. **Workers (FastPathThread):** do the actual DPI processing (SNI/HTTP/DNS extraction, rule matching)
3. **Deterministic hashing:** the same `FiveTuple` always produces the same hash, so it always routes to the same LB and the same worker

**Why deterministic hashing matters:**
```
Connection: 192.168.1.100:54321 -> 142.250.185.206:443

Packet 1 (SYN):          hash=687168912 -> LB-0 -> Worker-0
Packet 2 (SYN-ACK):      hash=687168912 -> LB-0 -> Worker-0  (same worker!)
Packet 3 (Client Hello): hash=687168912 -> LB-0 -> Worker-0  (same worker!)
Packet 4 (Data):         hash=687168912 -> LB-0 -> Worker-0  (same worker!)

All packets of this connection go to the same worker.
That worker can safely mutate the Connection object without locking,
because no other thread will ever touch that flow's state.
```

### Detailed Flow

#### Step 1: Reader Thread (plays the role of a NIC doing RSS)

```java
// MultiThreadedDPIEngine.process()
while (pcapReader.readNextPacket(rawPacket)) {
    stats.incTotalPackets();
    stats.addTotalBytes(rawPacket.data.length);

    ParsedPacket parsed = new ParsedPacket();
    if (!PacketParser.parse(cloned, parsed) || !parsed.hasIP) {
        continue;
    }

    FiveTuple tuple = buildFiveTuple(parsed);
    RoutedPacket routed = RoutedPacket.of(cloned, parsed, tuple);   // computes the hash once
    int lbIndex = routed.hash % NUM_LOAD_BALANCERS;

    lbInputQueues[lbIndex].put(routed);
}
```

Everything the downstream tiers need is packaged into one immutable object - `RoutedPacket` - so **parsing happens exactly once**, in the reader thread, not again inside the worker.

```java
// RoutedPacket.java
public static RoutedPacket of(RawPacket raw, ParsedPacket parsed, FiveTuple tuple) {
    int h = tuple.hashCode() & 0x7FFFFFFF;   // mask sign bit so % is never negative
    return new RoutedPacket(raw, parsed, tuple, h, false);
}
```

#### Step 2: Load Balancer Thread (Tier 1)

```java
// LoadBalancerThread.run()
while (true) {
    RoutedPacket packet = inputQueue.take();

    if (packet.sentinel) {
        for (BlockingQueue<RoutedPacket> q : ownWorkerQueues) {
            q.put(RoutedPacket.sentinel());   // propagate shutdown to my own workers
        }
        break;
    }

    // Tier-2 hashing: pick ONE of THIS load balancer's own workers
    int subIndex = (packet.hash / numLoadBalancers) % workersPerLb;
    ownWorkerQueues[subIndex].put(packet);
}
```

Each `LoadBalancerThread` only ever talks to its **own** slice of workers (`LB-0` -> `Worker-0`/`Worker-1`, `LB-1` -> `Worker-2`/`Worker-3` for the default 4-worker setup) - there's no shared dispatch structure between the two LBs, so they never contend with each other.

#### Step 3: Fast Path Thread (Tier 2, the actual worker)

```java
// FastPathThread.run()
while (true) {
    RoutedPacket packet = inputQueue.take();
    if (packet.sentinel) break;
    processPacket(packet);
}

private void processPacket(RoutedPacket packet) {
    Connection connection = flows.computeIfAbsent(packet.tuple, t -> new Connection(t));
    classifyFlow(packet.parsed, connection);          // SNI / HTTP Host / DNS extraction

    if (ruleManager.isBlocked(packet.tuple.getSrcIp(), connection.getAppType(), connection.getSni())) {
        connection.setAction(PacketAction.DROP);
        stats.incDroppedPackets();
    } else {
        connection.setAction(PacketAction.FORWARD);
        stats.incForwardedPackets();
    }
}
```

Note there's no `PacketParser.parse()` call here anymore - the reader thread already did it, and `packet.parsed` carries the result.

#### Step 4: Shutdown - the "Poison Pill" / Sentinel Pattern

When the pcap file is exhausted, the reader sends one sentinel `RoutedPacket` (an empty marker, `sentinel == true`) to each LB's input queue. Each LB forwards a sentinel to each of its own workers, then exits. Each worker sees the sentinel, exits its loop, and counts down a shared `CountDownLatch`:

```java
for (int lb = 0; lb < NUM_LOAD_BALANCERS; lb++) {
    lbInputQueues[lb].put(RoutedPacket.sentinel());
}
workerCompletionLatch.await(2, TimeUnit.MINUTES);  // main thread waits for all workers to finish
```

This avoids needing a `Thread.interrupt()` or a shared "running" boolean flag - the shutdown signal flows through the same queues as real data.

### Thread-Safe Queues

Java's `BlockingQueue` handles all the producer/consumer coordination that would otherwise need manual locking. `LinkedBlockingQueue.put()` blocks the producer when full and `.take()` blocks the consumer when empty:

```java
this.lbInputQueues[i] = new LinkedBlockingQueue<>(500);
this.workerQueues[i]  = new LinkedBlockingQueue<>(100);
```

---

## 7. Deep Dive: Each Component

### `PcapReader.java`

**Purpose:** Read network captures saved by Wireshark

**Key fields (`GlobalHeader`):**
```java
public class GlobalHeader {
    public long magicNumber;   // 0xa1b2c3d4 identifies PCAP (or byte-swapped 0xd4c3b2a1)
    public int versionMajor;   // Usually 2
    public int versionMinor;   // Usually 4
    public long snapLen;       // Max packet size captured
    public long network;       // 1 = Ethernet
}
```

**Key methods:**
- `open(filename)`: opens the file, validates the magic number, detects endianness
- `readNextPacket(raw)`: reads the next 16-byte packet header + its data into a `RawPacket`
- `close()`: releases the `RandomAccessFile`

### `PacketParser.java`

**Purpose:** Extract protocol fields from raw bytes

**Key method:**
```java
public static boolean parse(RawPacket raw, ParsedPacket parsed) {
    parseEthernet(...);         // MACs, EtherType
    if (parsed.etherType == ETHERTYPE_IPV4) {
        parseIPv4(...);         // IPs, protocol, TTL
        if (parsed.protocol == TCP) parseTCP(...);
        else if (parsed.protocol == UDP) parseUDP(...);
    }
    // remaining bytes become parsed.payloadData
}
```

### `SNIExtractor.java` / `HTTPHostExtractor.java` / `DNSExtractor.java`

**Purpose:** Extract domain names from TLS, HTTP, and DNS traffic - see [Section 8](#8-how-sni-extraction-works) for the TLS one in full detail.

```java
public static Optional<String> extract(byte[] payload, int offset, int length)      // SNIExtractor
public static Optional<String> extract(byte[] payload, int offset, int length)      // HTTPHostExtractor
public static Optional<String> extractQuery(byte[] payload, int offset, int length) // DNSExtractor
```

All three return `Optional<String>` rather than a nullable `String` - this forces callers to handle the "not found" case explicitly with `.isPresent()` instead of a null check.

### `types/FiveTuple.java`

```java
public class FiveTuple {
    private final long srcIp;      // 32-bit IP packed into a long
    private final long dstIp;
    private final int srcPort;     // 16-bit port
    private final int dstPort;
    private final byte protocol;   // TCP=6, UDP=17

    @Override
    public boolean equals(Object o) { /* compares all 5 fields */ }

    @Override
    public int hashCode() { return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol); }
}
```
`equals()`/`hashCode()` are what make `FiveTuple` usable as a `HashMap`/`ConcurrentHashMap` key - and `hashCode()` is the exact same value the multi-threaded engine reuses for Tier-1/Tier-2 routing (masked to non-negative in `RoutedPacket.of()`).

### `types/AppType.java`

```java
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC,
    GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM, NETFLIX,
    AMAZON, MICROSOFT, APPLE, WHATSAPP, TELEGRAM, TIKTOK,
    SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE;
}

public static AppType fromSni(String sni) {
    String lower = sni.toLowerCase();
    if (lower.contains("youtube") || lower.contains("ytimg")) return YOUTUBE;
    if (lower.contains("facebook") || lower.contains("fbcdn")) return FACEBOOK;
    // ... more substring patterns
    return HTTPS;   // fallback: it's HTTPS, just not a recognized provider
}
```

### `types/DPIStats.java`

```java
private final AtomicLong totalPackets = new AtomicLong(0);
private final AtomicLong forwardedPackets = new AtomicLong(0);
private final AtomicLong droppedPackets = new AtomicLong(0);
// ...
public void incTotalPackets() { totalPackets.incrementAndGet(); }
```
`AtomicLong` is what makes these counters safe to increment from 4+ worker threads at once without a `synchronized` block - each `incrementAndGet()` is a single atomic CPU instruction (compare-and-swap), not a read-modify-write that could race.

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
+----------+                              +----------+
|  Browser |                              |  Server  |
+----+-----+                              +----+-----+
     |                                         |
     | ---- Client Hello --------------------->|
     |      (includes SNI: www.youtube.com)    |
     |                                         |
     | <--- Server Hello ---------------------- |
     |      (includes certificate)             |
     |                                         |
     | ---- Key Exchange ---------------------->|
     |                                         |
     | <=== Encrypted Data ===================> |
     |      (from here on, everything is       |
     |       encrypted - we can't see it)      |
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" <- THE GOAL!
```

### Our Extraction Code (`SNIExtractor.java`, real, not simplified)

```java
public static Optional<String> extract(byte[] payload, int offset, int length) {
    if (!isTLSClientHello(payload, offset, length)) {
        return Optional.empty();
    }

    int pos = offset + 5;   // skip TLS record header
    pos += 4;                // skip handshake type + length
    pos += 2;                // skip client version
    pos += 32;                // skip Random

    int sessionIdLength = payload[pos] & 0xFF;
    pos += 1 + sessionIdLength;                              // skip Session ID

    int cipherSuitesLength = readUint16BE(payload, pos);
    pos += 2 + cipherSuitesLength;                            // skip Cipher Suites

    int compressionMethodsLength = payload[pos] & 0xFF;
    pos += 1 + compressionMethodsLength;                      // skip Compression Methods

    int extensionsLength = readUint16BE(payload, pos);
    pos += 2;
    int extensionsEnd = Math.min(pos + extensionsLength, offset + length);

    while (pos + 4 <= extensionsEnd) {
        short extensionType = (short) readUint16BE(payload, pos);
        int extensionLength = readUint16BE(payload, pos + 2);
        pos += 4;

        if (extensionType == EXTENSION_SNI) {           // 0x0000
            int sniLength = readUint16BE(payload, pos + 3);
            byte sniType = payload[pos + 2];
            if (sniType == SNI_TYPE_HOSTNAME) {
                return Optional.of(new String(payload, pos + 5, sniLength, "UTF-8"));
            }
        }
        pos += extensionLength;   // not SNI - skip to the next extension
    }

    return Optional.empty();   // SNI not found in this Client Hello
}

private static int readUint16BE(byte[] data, int offset) {
    return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
}
```

`readUint16BE` reads a big-endian 16-bit value by hand with bit-shifting, since Java has no built-in "read big-endian short from a byte array offset" primitive outside of `ByteBuffer`.

For HTTP (`HTTPHostExtractor.java`), it's much simpler because HTTP is plaintext - just a case-insensitive substring search for `"Host:"` followed by reading until the next `\r` or `\n`. For DNS (`DNSExtractor.java`), the domain is decoded from its length-prefixed label format (`3www6google3com0` -> `www.google.com`).

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|-----------------|
| IP | `--block-ip 192.168.1.50` | All traffic from this source |
| App | `--block-app YouTube` | All connections classified as this `AppType` |
| Domain | `--block-domain tiktok` | Any SNI containing this substring |

### The Blocking Flow

```
Packet arrives
      |
      v
+---------------------------------+
| Is source IP in blocked list?  |--Yes--> mark DROP
+---------------+-----------------+
                |No
                v
+---------------------------------+
| Is app type in blocked list?   |--Yes--> mark DROP
+---------------+-----------------+
                |No
                v
+---------------------------------+
| Does SNI contain a blocked     |--Yes--> mark DROP
| domain substring?              |
+---------------+-----------------+
                |No
                v
            mark FORWARD
```

### Flow-Based Blocking

**Important:** blocking is decided at the *flow* level, not the packet level - because we can't identify the app until we've seen the Client Hello.

```
Connection to YouTube:
  Packet 1 (SYN)           -> No SNI yet, AppType=UNKNOWN -> FORWARD
  Packet 2 (SYN-ACK)       -> No SNI yet                  -> FORWARD
  Packet 3 (ACK)           -> No SNI yet                  -> FORWARD
  Packet 4 (Client Hello)  -> SNI: www.youtube.com
                           -> AppType: YOUTUBE (blocked!)
                           -> connection.setAction(DROP)
  Packet 5 (Data)          -> AppType already YOUTUBE      -> DROP
  Packet 6 (Data)          -> AppType already YOUTUBE      -> DROP
```


---

## 10. Building and Running

### Prerequisites

- **JDK 11 or newer** (built and tested against JDK 21) - you need the full JDK (`javac`), not just a JRE
- No external libraries / no Maven or Gradle required - plain `javac`/`java` is enough

Check your version:
```powershell
java -version
javac -version
```

### Build Commands

From the project root, compile every package in one go:

**Windows PowerShell:**
```powershell
javac -d bin -cp src\main\java `
  src\main\java\com\dpi\types\*.java `
  src\main\java\com\dpi\parser\*.java `
  src\main\java\com\dpi\extractor\*.java `
  src\main\java\com\dpi\pcap\*.java `
  src\main\java\com\dpi\threading\*.java `
  src\main\java\com\dpi\engine\*.java
```

**macOS/Linux:**
```bash
javac -d bin -cp src/main/java \
  src/main/java/com/dpi/types/*.java \
  src/main/java/com/dpi/parser/*.java \
  src/main/java/com/dpi/extractor/*.java \
  src/main/java/com/dpi/pcap/*.java \
  src/main/java/com/dpi/threading/*.java \
  src/main/java/com/dpi/engine/*.java
```

No errors means it worked - `.class` files will appear under `bin/com/dpi/...`.

### Running

**Single-threaded, basic usage:**
```powershell
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap
```

**Multi-threaded (2-tier hierarchical), basic usage:**
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap --threads 4
```

**With blocking rules:**
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output_mt.pcap `
  --threads 4 `
  --block-app YouTube `
  --block-ip 192.168.1.50 `
  --block-domain facebook
```

**Configure thread count (multi-threaded only):**
```powershell
java -cp bin com.dpi.engine.MultiThreadedDPIEngine input.pcap output.pcap --threads 8
# 8 total workers, split evenly as 2 load balancers x 4 workers each
```
`--threads N` sets the **total** worker count, always split evenly across the 2 load balancers. An odd number is rounded up by 1 (e.g. `--threads 5` becomes 6 = 2x3).

### Creating Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output (Multi-threaded, `--threads 4 --block-app YouTube`, real run)

```
[Rules] Blocked app: YouTube
Opened PCAP file: test_dpi.pcap
  Version: 2.4
  Snaplen: 65535 bytes
Starting Multi-Threaded DPI Processing (2-tier hierarchical): 2 load balancers x 2 workers = 4 total worker threads...
[LB-0] flow-hash=687168912 -> Worker-0 (local slot 0)
[LB-1] flow-hash=1196672963 -> Worker-3 (local slot 1)
...
All packets routed (77). Waiting for processing...

+==================================================================+
|                      PROCESSING REPORT                          |
+==================================================================+
| Total Packets:                77                                |
| Total Bytes:                  5738                               |
| TCP Packets:                  73                                 |
| UDP Packets:                  4                                  |
+==================================================================+
| Forwarded:                    76                                 |
| Dropped:                      1                                  |
+==================================================================+

[Detected Domains/SNIs]
  - api.twitter.com -> DNS
  - discord.com -> Discord
  - www.google.com -> Google
  - www.youtube.com -> DNS
  ...
DPI processing completed successfully
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| `[Rules]` lines | Which blocking rules are active for this run |
| `Starting Multi-Threaded...` | Confirms the 2-tier layout actually created (LBs x workers) |
| `[LB-x] flow-hash=... -> Worker-y` | The real Tier-1/Tier-2 routing decision for that flow, printed live |
| Total Packets | Packets read from the input file |
| Forwarded / Dropped | In-memory classification result (see the [Section 9](#9-how-blocking-works) note - no output file is written yet) |
| Detected Domains/SNIs | Every distinct domain the engine actually extracted, and what it was classified as |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Write the actual filtered output file** (closes the gap noted in Sections 5 & 9)
   ```java
   // A new PcapWriter class, used only when action == FORWARD
   public void writePacket(RawPacket raw) throws IOException {
       out.write(serializeHeader(raw.header));
       out.write(raw.data);
   }
   ```

2. **Add More App Signatures**
   ```java
   // In AppType.fromSni()
   if (lower.contains("twitch")) return TWITCH;
   ```

3. **Fix the multi-threaded report's domain de-duplication bug**
   `MultiThreadedDPIEngine.generateReport()` currently dedupes by SNI *string* with `findFirst()`, so if the same domain appears via two different flows with different `AppType`s (e.g. a DNS query and a TLS connection both to `youtube.com`), only one shows up. The single-threaded `DPIEngine` avoids this by deduping on the `Connection` object instead. Worth fixing to match.

4. **Add IPv6 and QUIC/HTTP3 Support**
   - QUIC uses UDP on port 443; its SNI-equivalent is inside an encrypted "Initial" packet and needs different handling than plain TLS-over-TCP

5. **TCP Reassembly**
   - Right now `SNIExtractor` only looks inside a single TCP segment. If a Client Hello is split across 2+ TCP segments (common with large certificate lists), it will be missed. Reassembling the TCP stream before SNI extraction would fix this.

6. **Persistent Rules**
   - Load `--block-*` rules from a config file at startup instead of only from command-line args

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - understanding packet structure, using `ByteBuffer`/`ByteOrder` to correctly read big-endian network fields
2. **Deep Packet Inspection** - looking inside encrypted connections via the TLS SNI leak
3. **Flow Tracking** - managing stateful connections in a `ConcurrentHashMap<FiveTuple, Connection>`
4. **2-Tier Hierarchical Multi-threading** - `ExecutorService` + `BlockingQueue` + deterministic hash routing for flow affinity, no locks needed per-flow
5. **Producer-Consumer Pattern with a Poison Pill** - clean shutdown propagated through the same queues as real data, via `CountDownLatch`

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with the simple version (`DPIEngine.java`) to understand the concepts, then move to the multi-threaded version (`MultiThreadedDPIEngine.java`, `LoadBalancerThread.java`, `FastPathThread.java`) to see how the 2-tier hierarchy is built.
