package com.dpi.types;

import java.util.Objects;

/**
 * FiveTuple: Uniquely identifies a network connection/flow
 * Consists of: source IP, destination IP, source port, destination port, and protocol
 */
public class FiveTuple {
    private final long srcIp;      // 32-bit IP address
    private final long dstIp;      // 32-bit IP address
    private final int srcPort;     // 16-bit port
    private final int dstPort;     // 16-bit port
    private final byte protocol;   // TCP=6, UDP=17

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, byte protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public long getSrcIp() {
        return srcIp;
    }

    public long getDstIp() {
        return dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public byte getProtocol() {
        return protocol;
    }

    /**
     * Create reverse tuple (for matching bidirectional flows)
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple that = (FiveTuple) o;
        return srcIp == that.srcIp &&
               dstIp == that.dstIp &&
               srcPort == that.srcPort &&
               dstPort == that.dstPort &&
               protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        String srcIpStr = formatIp(srcIp);
        String dstIpStr = formatIp(dstIp);
        String protocolStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "?";
        return String.format("%s:%d -> %s:%d (%s)", srcIpStr, srcPort, dstIpStr, dstPort, protocolStr);
    }

    private static String formatIp(long ip) {
        return String.format("%d.%d.%d.%d",
            (ip >> 0) & 0xFF,
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF);
    }
}