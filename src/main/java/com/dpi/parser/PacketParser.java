package com.dpi.parser;

import com.dpi.pcap.RawPacket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketParser {
    public static final byte ICMP = 1;
    public static final byte TCP = 6;
    public static final byte UDP = 17;
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP = 0x0806;

    public static class TCPFlags {
        public static final byte FIN = 0x01;
        public static final byte SYN = 0x02;
        public static final byte RST = 0x04;
        public static final byte PSH = 0x08;
        public static final byte ACK = 0x10;
        public static final byte URG = 0x20;
    }

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int offset = 0;

        if (!parseEthernet(data, parsed, offset)) {
            return false;
        }
        offset += 14;

        if (parsed.etherType == ETHERTYPE_IPV4) {
            if (!parseIPv4(data, parsed, offset)) {
                return false;
            }

            int versionIHL = data[offset] & 0xFF;
            int ihl = (versionIHL & 0x0F) * 4;
            offset += ihl;

            if (parsed.protocol == TCP) {
                if (!parseTCP(data, parsed, offset)) {
                    return false;
                }
                int dataOffset = (data[offset + 12] & 0xFF) >> 4;
                int tcpHeaderLen = dataOffset * 4;
                offset += tcpHeaderLen;
            } else if (parsed.protocol == UDP) {
                if (!parseUDP(data, parsed, offset)) {
                    return false;
                }
                offset += 8;
            }
        }

        if (offset < data.length) {
            parsed.payloadLength = data.length - offset;
            parsed.payloadData = new byte[parsed.payloadLength];
            System.arraycopy(data, offset, parsed.payloadData, 0, parsed.payloadLength);
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, ParsedPacket parsed, int offset) {
        if (data.length < offset + 14) return false;
        parsed.destMac = macToString(data, offset);
        parsed.srcMac = macToString(data, offset + 6);
        ByteBuffer bb = ByteBuffer.wrap(data, offset + 12, 2);
        bb.order(ByteOrder.BIG_ENDIAN);
        parsed.etherType = bb.getShort() & 0xFFFF;
        return true;
    }

    private static boolean parseIPv4(byte[] data, ParsedPacket parsed, int offset) {
        if (data.length < offset + 20) return false;
        int versionIHL = data[offset] & 0xFF;
        parsed.ipVersion = (versionIHL >> 4) & 0x0F;
        int ihl = (versionIHL & 0x0F);
        if (parsed.ipVersion != 4) return false;
        int ipHeaderLen = ihl * 4;
        if (data.length < offset + ipHeaderLen) return false;
        parsed.ttl = data[offset + 8];
        parsed.protocol = data[offset + 9];
        parsed.srcIp = ipToString(data, offset + 12);
        parsed.destIp = ipToString(data, offset + 16);
        parsed.hasIP = true;
        return true;
    }

    private static boolean parseTCP(byte[] data, ParsedPacket parsed, int offset) {
        if (data.length < offset + 20) return false;
        ByteBuffer bb = ByteBuffer.wrap(data, offset, 20);
        bb.order(ByteOrder.BIG_ENDIAN);
        parsed.srcPort = bb.getShort() & 0xFFFF;
        parsed.destPort = bb.getShort() & 0xFFFF;
        parsed.seqNumber = bb.getInt() & 0xFFFFFFFFL;
        parsed.ackNumber = bb.getInt() & 0xFFFFFFFFL;
        int dataOffset = (data[offset + 12] & 0xFF) >> 4;
        int tcpHeaderLen = dataOffset * 4;
        if (tcpHeaderLen < 20 || data.length < offset + tcpHeaderLen) return false;
        parsed.tcpFlags = data[offset + 13];
        parsed.hasTCP = true;
        return true;
    }

    private static boolean parseUDP(byte[] data, ParsedPacket parsed, int offset) {
        if (data.length < offset + 8) return false;
        ByteBuffer bb = ByteBuffer.wrap(data, offset, 8);
        bb.order(ByteOrder.BIG_ENDIAN);
        parsed.srcPort = bb.getShort() & 0xFFFF;
        parsed.destPort = bb.getShort() & 0xFFFF;
        parsed.hasUDP = true;
        return true;
    }

    public static String macToString(byte[] mac, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", mac[offset + i]));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] ip, int offset) {
        return String.format("%d.%d.%d.%d",
            ip[offset] & 0xFF, ip[offset + 1] & 0xFF, 
            ip[offset + 2] & 0xFF, ip[offset + 3] & 0xFF);
    }

    public static String protocolToString(byte protocol) {
        switch (protocol) {
            case ICMP: return "ICMP";
            case TCP: return "TCP";
            case UDP: return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(byte flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0) sb.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0) sb.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0) sb.append("FIN ");
        if ((flags & TCPFlags.RST) != 0) sb.append("RST ");
        if ((flags & TCPFlags.PSH) != 0) sb.append("PSH ");
        if ((flags & TCPFlags.URG) != 0) sb.append("URG ");
        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }
}