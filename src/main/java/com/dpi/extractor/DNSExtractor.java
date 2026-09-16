package com.dpi.extractor;

import java.util.Optional;
public class DNSExtractor {
    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) {
            return Optional.empty();
        }

        int pos = offset + 12;
        StringBuilder domain = new StringBuilder();

        while (pos < offset + length) {
            int labelLength = payload[pos] & 0xFF;
            if (labelLength == 0) break;
            if (labelLength > 63) break;

            pos++;
            if (pos + labelLength > offset + length) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, pos, labelLength));
            pos += labelLength;
        }

        return domain.length() > 0 ? Optional.of(domain.toString()) : Optional.empty();
    }

    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        byte flags = payload[offset + 2];
        if ((flags & 0x80) != 0) return false;
        int qdcount = (((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF));
        return qdcount > 0;
    }
}