package com.dpi.engine;

import com.dpi.pcap.RawPacket;
import com.dpi.parser.*;
import com.dpi.extractor.*;
import com.dpi.types.*;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;

/**
 * FastPathThread processes packets assigned by the load balancer.
 * Each worker thread performs:
 * - Packet parsing
 * - Application classification
 * - Rule application
 * - Statistics tracking
 */
public class FastPathThread implements Runnable {
    private final BlockingQueue<RawPacket> inputQueue;
    private final Map<FiveTuple, Connection> flows;
    private final RuleManager ruleManager;
    private final DPIStats stats;
    private final CountDownLatch completionLatch;

    public FastPathThread(BlockingQueue<RawPacket> inputQueue,
                         Map<FiveTuple, Connection> flows,
                         RuleManager ruleManager,
                         DPIStats stats,
                         CountDownLatch completionLatch) {
        this.inputQueue = inputQueue;
        this.flows = flows;
        this.ruleManager = ruleManager;
        this.stats = stats;
        this.completionLatch = completionLatch;
    }

    @Override
    public void run() {
        try {
            while (true) {
                RawPacket rawPacket = inputQueue.take();

                // Check for sentinel value (empty data array)
                if (rawPacket.data.length == 0) {
                    break;
                }

                processPacket(rawPacket);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("FastPathThread interrupted");
        } finally {
            completionLatch.countDown();
        }
    }

    private void processPacket(RawPacket rawPacket) {
        stats.incTotalPackets();
        stats.addTotalBytes(rawPacket.data.length);

        // Parse packet
        ParsedPacket parsed = new ParsedPacket();
        if (!PacketParser.parse(rawPacket, parsed)) {
            return;
        }

        // Track protocol statistics
        if (parsed.hasTCP) {
            stats.incTcpPackets();
        } else if (parsed.hasUDP) {
            stats.incUdpPackets();
        }

        // Extract five-tuple
        FiveTuple tuple = extractFiveTuple(parsed);
        if (tuple == null) {
            return;
        }

        // Get or create connection
        Connection connection = flows.computeIfAbsent(tuple, t -> new Connection(t));

        // Classify flow
        classifyFlow(parsed, connection);

        // Apply rules
        if (ruleManager.isBlocked(tuple.getSrcIp(), connection.getAppType(), 
                                 connection.getSni())) {
            connection.setAction(PacketAction.DROP);
            stats.incDroppedPackets();
        } else {
            connection.setAction(PacketAction.FORWARD);
            stats.incForwardedPackets();
        }

        connection.incPacketsIn();
        connection.addBytesIn(rawPacket.data.length);
        connection.updateLastSeen();
    }

    private FiveTuple extractFiveTuple(ParsedPacket parsed) {
        if (!parsed.hasIP) {
            return null;
        }

        long srcIp = parseIP(parsed.srcIp);
        long dstIp = parseIP(parsed.destIp);

        return new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);
    }

    private void classifyFlow(ParsedPacket parsed, Connection connection) {
        if (connection.getState() == ConnectionState.CLASSIFIED) {
            return;
        }

        if (parsed.destPort == 443 && parsed.payloadLength > 5) {
            Optional<String> sni = SNIExtractor.extract(parsed.payloadData, 0, parsed.payloadLength);
            if (sni.isPresent()) {
                connection.setSni(sni.get());
                connection.setAppType(AppType.fromSni(sni.get()));
                connection.setState(ConnectionState.CLASSIFIED);
            }
        } else if (parsed.destPort == 80 && parsed.payloadLength > 5) {
            Optional<String> host = HTTPHostExtractor.extract(parsed.payloadData, 0, parsed.payloadLength);
            if (host.isPresent()) {
                connection.setSni(host.get());
                connection.setAppType(AppType.HTTPS);
                connection.setState(ConnectionState.CLASSIFIED);
            }
        } else if (parsed.destPort == 53 && parsed.payloadLength > 5) {
            Optional<String> domain = DNSExtractor.extractQuery(parsed.payloadData, 0, parsed.payloadLength);
            if (domain.isPresent()) {
                connection.setSni(domain.get());
                connection.setAppType(AppType.DNS);
                connection.setState(ConnectionState.CLASSIFIED);
            }
        }
    }

    private long parseIP(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (String part : parts) {
            result = (result << 8) | (Long.parseLong(part) & 0xFF);
        }
        return result;
    }
}
