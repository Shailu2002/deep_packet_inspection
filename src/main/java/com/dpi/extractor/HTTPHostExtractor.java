package com.dpi.extractor;
import java.util.Optional;

public class HTTPHostExtractor {
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) {
            return Optional.empty();
        }

        String payloadStr = new String(payload, offset, length);
        int hostIndex = payloadStr.toLowerCase().indexOf("host:");
        
        if (hostIndex == -1) {
            return Optional.empty();
        }

        int start = hostIndex + 5;
        while (start < payloadStr.length() && 
               (payloadStr.charAt(start) == ' ' || payloadStr.charAt(start) == '\t')) {
            start++;
        }

        int end = start;
        while (end < payloadStr.length() && 
               payloadStr.charAt(end) != '\r' && payloadStr.charAt(end) != '\n') {
            end++;
        }

        if (end > start) {
            String host = payloadStr.substring(start, end);
            int colonPos = host.indexOf(':');
            if (colonPos != -1) {
                host = host.substring(0, colonPos);
            }
            return Optional.of(host);
        }

        return Optional.empty();
    }

    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        for (String method : methods) {
            if (startsWithBytes(payload, offset, method.getBytes())) {
                return true;
            }
        }
        return false;
    }

    private static boolean startsWithBytes(byte[] data, int offset, byte[] prefix) {
        if (data.length - offset < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[offset + i] != prefix[i]) return false;
        }
        return true;
    }
}
