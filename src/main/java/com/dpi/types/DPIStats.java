package com.dpi.types;

import java.util.concurrent.atomic.AtomicLong;

public class DPIStats {
    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong totalBytes = new AtomicLong(0);
    private final AtomicLong forwardedPackets = new AtomicLong(0);
    private final AtomicLong droppedPackets = new AtomicLong(0);
    private final AtomicLong tcpPackets = new AtomicLong(0);
    private final AtomicLong udpPackets = new AtomicLong(0);
    private final AtomicLong otherPackets = new AtomicLong(0);
    private final AtomicLong activeConnections = new AtomicLong(0);

    public void incTotalPackets() { totalPackets.incrementAndGet(); }
    public void addTotalBytes(long bytes) { totalBytes.addAndGet(bytes); }
    public void incForwardedPackets() { forwardedPackets.incrementAndGet(); }
    public void incDroppedPackets() { droppedPackets.incrementAndGet(); }
    public void incTcpPackets() { tcpPackets.incrementAndGet(); }
    public void incUdpPackets() { udpPackets.incrementAndGet(); }
    public void incOtherPackets() { otherPackets.incrementAndGet(); }
    public void incActiveConnections() { activeConnections.incrementAndGet(); }
    public void decActiveConnections() { activeConnections.decrementAndGet(); }

    public long getTotalPackets() { return totalPackets.get(); }
    public long getTotalBytes() { return totalBytes.get(); }
    public long getForwardedPackets() { return forwardedPackets.get(); }
    public long getDroppedPackets() { return droppedPackets.get(); }
    public long getTcpPackets() { return tcpPackets.get(); }
    public long getUdpPackets() { return udpPackets.get(); }
    public long getOtherPackets() { return otherPackets.get(); }
    public long getActiveConnections() { return activeConnections.get(); }
}