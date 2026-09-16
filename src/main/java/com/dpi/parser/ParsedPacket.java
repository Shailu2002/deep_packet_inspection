package com.dpi.parser;

public class ParsedPacket {
    public long timestampSec;
    public long timestampUsec;
    public String srcMac;
    public String destMac;
    public int etherType;
    public boolean hasIP;
    public int ipVersion;
    public String srcIp;
    public String destIp;
    public byte protocol;
    public byte ttl;
    public boolean hasTCP;
    public boolean hasUDP;
    public int srcPort;
    public int destPort;
    public byte tcpFlags;
    public long seqNumber;
    public long ackNumber;
    public int payloadLength;
    public byte[] payloadData;

    public ParsedPacket() {
        this.srcMac = "";
        this.destMac = "";
        this.srcIp = "";
        this.destIp = "";
        this.payloadData = new byte[0];
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(srcMac).append(" -> ").append(destMac);
        if (hasIP) {
            sb.append(" | ").append(srcIp).append(":").append(srcPort)
              .append(" -> ").append(destIp).append(":").append(destPort);
        }
        sb.append(" | Payload: ").append(payloadLength).append(" bytes");
        return sb.toString();
    }
}