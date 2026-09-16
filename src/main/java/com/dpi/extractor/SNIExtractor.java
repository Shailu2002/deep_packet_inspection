package com.dpi.extractor;

import java.util.Optional;

public class SNIExtractor {
    private static final byte CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final byte HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final short EXTENSION_SNI = 0x0000;
    private static final byte SNI_TYPE_HOSTNAME = 0x00;

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) {
            return Optional.empty();
        }

        try {
            int pos = offset + 5;

            if (pos + 4 > offset + length) return Optional.empty();
            pos += 4;

            if (pos + 2 > offset + length) return Optional.empty();
            pos += 2;

            if (pos + 32 > offset + length) return Optional.empty();
            pos += 32;

            if (pos >= offset + length) return Optional.empty();
            int sessionIdLength = payload[pos] & 0xFF;
            pos += 1 + sessionIdLength;

            if (pos + 2 > offset + length) return Optional.empty();
            int cipherSuitesLength = readUint16BE(payload, pos);
            pos += 2 + cipherSuitesLength;

            if (pos >= offset + length) return Optional.empty();
            int compressionMethodsLength = payload[pos] & 0xFF;
            pos += 1 + compressionMethodsLength;

            if (pos + 2 > offset + length) return Optional.empty();
            int extensionsLength = readUint16BE(payload, pos);
            pos += 2;

            int extensionsEnd = Math.min(pos + extensionsLength, offset + length);

            while (pos + 4 <= extensionsEnd) {
                short extensionType = (short) readUint16BE(payload, pos);
                int extensionLength = readUint16BE(payload, pos + 2);
                pos += 4;

                if (pos + extensionLength > extensionsEnd) break;

                if (extensionType == EXTENSION_SNI) {
                    if (extensionLength < 5) break;

                    int sniListLength = readUint16BE(payload, pos);
                    if (sniListLength < 3) break;

                    byte sniType = payload[pos + 2];
                    int sniLength = readUint16BE(payload, pos + 3);

                    if (sniType != SNI_TYPE_HOSTNAME) break;
                    if (sniLength > extensionLength - 5) break;

                    String sni = new String(payload, pos + 5, sniLength, "UTF-8");
                    return Optional.of(sni);
                }

                pos += extensionLength;
            }
        } catch (Exception e) {
            return Optional.empty();
        }

        return Optional.empty();
    }

    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;
        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;
        int recordLength = readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) return false;
        if ((payload[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;
        return true;
    }

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}



