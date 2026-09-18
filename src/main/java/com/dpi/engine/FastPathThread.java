package com.dpi.engine;

import com.dpi.threading.RoutedPacket;
import com.dpi.parser.ParsedPacket;
import com.dpi.extractor.*;
import com.dpi.types.*;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;

public class FastPathThread implements Runnable {
    private final String name;
    private final BlockingQueue<RoutedPacket> inputQueue;
    private final Map<FiveTuple, Connection> flows;
    private final RuleManager ruleManager;
    private final DPIStats stats;
    private final CountDownLatch completionLatch;

    public FastPathThread(String name,
            BlockingQueue<RoutedPacket> inputQueue,
            Map<FiveTuple, Connection> flows,
            RuleManager ruleManager,
            DPIStats stats,
            CountDownLatch completionLatch) {
        this.name = name;
        this.inputQueue = inputQueue;
        this.flows = flows;
        this.ruleManager = ruleManager;
        this.stats = stats;
        this.completionLatch = completionLatch;
    }

    @Override
    public void run() {
        Thread.currentThread().setName(name);
        try {
            while (true) {
                RoutedPacket packet = inputQueue.take();

                if (packet.sentinel) {
                    break;
                }

                processPacket(packet);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println(name + " interrupted");
        } finally {
            completionLatch.countDown();
        }
    }

    private void processPacket(RoutedPacket packet) {
        ParsedPacket parsed = packet.parsed;
        FiveTuple tuple = packet.tuple;

        Connection connection = flows.computeIfAbsent(tuple, t -> new Connection(t));

        classifyFlow(parsed, connection);

        if (ruleManager.isBlocked(tuple.getSrcIp(), connection.getAppType(),
                connection.getSni())) {
            connection.setAction(PacketAction.DROP);
            stats.incDroppedPackets();
        } else {
            connection.setAction(PacketAction.FORWARD);
            stats.incForwardedPackets();
        }

        connection.incPacketsIn();
        connection.addBytesIn(packet.raw.data.length);
        connection.updateLastSeen();
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
}