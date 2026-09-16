package com.dpi.pcap;

public class RawPacket {
    public static class PacketHeader {
        public long tsSec;
        public long tsUsec;
        public long inclLen;
        public long origLen;

        @Override
        public String toString() {
            return String.format("PacketHeader{ts=%d.%06d, len=%d/%d}", 
                tsSec, tsUsec, inclLen, origLen);
        }
    }

    public PacketHeader header;
    public byte[] data;

    public RawPacket() {
        this.header = new PacketHeader();
        this.data = new byte[0];
    }

    public RawPacket(PacketHeader header, byte[] data) {
        this.header = header;
        this.data = data;
    }
}