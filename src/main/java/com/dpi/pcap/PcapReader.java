package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader {
    private static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    public static class GlobalHeader {
        public long magicNumber;
        public int versionMajor;
        public int versionMinor;
        public long thisZone;
        public long sigFigs;
        public long snapLen;
        public long network;
    }

    private RandomAccessFile file;
    private GlobalHeader globalHeader;
    private boolean needsByteSwap;

    public boolean open(String filename) throws IOException {
        close();

        this.file = new RandomAccessFile(filename, "r");

        byte[] headerBytes = new byte[24];
        if (file.read(headerBytes) != 24) {
            System.err.println("Error: Could not read PCAP global header");
            close();
            return false;
        }

        globalHeader = new GlobalHeader();
        ByteBuffer bb = ByteBuffer.wrap(headerBytes);
        bb.order(ByteOrder.LITTLE_ENDIAN);

        globalHeader.magicNumber = bb.getInt() & 0xFFFFFFFFL;

        if (globalHeader.magicNumber == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false;
        } else if (globalHeader.magicNumber == PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;
            bb.order(ByteOrder.BIG_ENDIAN);
            bb.rewind();
            globalHeader.magicNumber = bb.getInt() & 0xFFFFFFFFL;
        } else {
            System.err.println("Error: Invalid PCAP magic number: 0x" + 
                Long.toHexString(globalHeader.magicNumber));
            close();
            return false;
        }

        globalHeader.versionMajor = bb.getShort() & 0xFFFF;
        globalHeader.versionMinor = bb.getShort() & 0xFFFF;
        globalHeader.thisZone = bb.getInt() & 0xFFFFFFFFL;
        globalHeader.sigFigs = bb.getInt() & 0xFFFFFFFFL;
        globalHeader.snapLen = bb.getInt() & 0xFFFFFFFFL;
        globalHeader.network = bb.getInt() & 0xFFFFFFFFL;

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
        System.out.println("  Snaplen: " + globalHeader.snapLen + " bytes");

        return true;
    }

    public boolean readNextPacket(RawPacket packet) throws IOException {
        if (file == null || !file.getChannel().isOpen()) {
            return false;
        }

        byte[] headerBytes = new byte[16];
        int read = file.read(headerBytes);
        if (read != 16) {
            return false;
        }

        ByteBuffer bb = ByteBuffer.wrap(headerBytes);
        if (needsByteSwap) {
            bb.order(ByteOrder.BIG_ENDIAN);
        } else {
            bb.order(ByteOrder.LITTLE_ENDIAN);
        }

        packet.header.tsSec = bb.getInt() & 0xFFFFFFFFL;
        packet.header.tsUsec = bb.getInt() & 0xFFFFFFFFL;
        packet.header.inclLen = bb.getInt() & 0xFFFFFFFFL;
        packet.header.origLen = bb.getInt() & 0xFFFFFFFFL;

        if (packet.header.inclLen > globalHeader.snapLen || packet.header.inclLen > 65535) {
            System.err.println("Error: Invalid packet length: " + packet.header.inclLen);
            return false;
        }

        packet.data = new byte[(int) packet.header.inclLen];
        read = file.read(packet.data);
        if (read != packet.header.inclLen) {
            System.err.println("Error: Could not read packet data");
            return false;
        }

        return true;
    }

    public void close() throws IOException {
        if (file != null) {
            file.close();
            file = null;
        }
    }

    public GlobalHeader getGlobalHeader() { return globalHeader; }
    public boolean isOpen() { return file != null; }
    public boolean needsByteSwap() { return needsByteSwap; }
}