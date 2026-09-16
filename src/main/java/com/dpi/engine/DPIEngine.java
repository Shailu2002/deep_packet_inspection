package com.dpi.engine;

import com.dpi.pcap.*;
import com.dpi.parser.*;
import com.dpi.extractor.*;
import com.dpi.types.*;
import java.util.*;
import java.util.concurrent.*;

public class DPIEngine {
    private PcapReader pcapReader;
    private RuleManager ruleManager;
    private Map<FiveTuple, Connection> flows;
    private DPIStats stats;
    private String inputFile;

    public DPIEngine(String inputFile, String outputFile) {
        this.inputFile = inputFile;
        this.pcapReader = new PcapReader();
        this.ruleManager = new RuleManager();
        this.flows = new ConcurrentHashMap<>();
        this.stats = new DPIStats();
    }

    public boolean process() {
        try {
            if (!pcapReader.open(inputFile)) {
                System.err.println("Failed to open PCAP file");
                return false;
            }

            System.out.println("Starting DPI processing...");

            RawPacket rawPacket = new RawPacket();
            int packetCount = 0;

            while (pcapReader.readNextPacket(rawPacket)) {
                stats.incTotalPackets();
                stats.addTotalBytes(rawPacket.data.length);

                ParsedPacket parsed = new ParsedPacket();
                if (!PacketParser.parse(rawPacket, parsed)) {
                    continue;
                }

                FiveTuple tuple = extractFiveTuple(parsed);
                if (tuple == null) {
                    continue;
                }

                // Track protocol statistics
                if (parsed.hasTCP) {
                    stats.incTcpPackets();
                } else if (parsed.hasUDP) {
                    stats.incUdpPackets();
                }

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
                connection.addBytesIn(rawPacket.data.length);

                packetCount++;
                if (packetCount % 100 == 0) {
                    System.out.println("Processed " + packetCount + " packets");
                }
            }

            pcapReader.close();
            generateReport();
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
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

    private void generateReport() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Total Packets:                " + padValue(stats.getTotalPackets()));
        System.out.println("║ Total Bytes:                  " + padValue(stats.getTotalBytes()));
        System.out.println("║ TCP Packets:                  " + padValue(stats.getTcpPackets()));
        System.out.println("║ UDP Packets:                  " + padValue(stats.getUdpPackets()));
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Forwarded:                    " + padValue(stats.getForwardedPackets()));
        System.out.println("║ Dropped:                      " + padValue(stats.getDroppedPackets()));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        System.out.println("\n[Detected Domains/SNIs]");
        flows.values().stream()
            .filter(c -> !c.getSni().isEmpty())
            .sorted(Comparator.comparing(Connection::getSni))
            .distinct()
            .forEach(c -> {
                System.out.printf("  - %s -> %s%n", c.getSni(), 
                    AppType.toDisplayString(c.getAppType()));
            });
    }

    private long parseIP(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i]) << (i * 8));
        }
        return result;
    }

    private String padValue(long value) {
        return String.format("%-30d", value) + " ║";
    }

    public void addBlockRule(String type, String value) {
        ruleManager.addRule(type, value);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java DPIEngine <input.pcap> <output.pcap> [--block-app APP] [--block-domain DOMAIN]");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        DPIEngine engine = new DPIEngine(inputFile, outputFile);

        for (int i = 2; i < args.length; i++) {
            if (args[i].equals("--block-app") && i + 1 < args.length) {
                engine.addBlockRule("app", args[i + 1]);
                i++;
            } else if (args[i].equals("--block-domain") && i + 1 < args.length) {
                engine.addBlockRule("domain", args[i + 1]);
                i++;
            } else if (args[i].equals("--block-ip") && i + 1 < args.length) {
                engine.addBlockRule("ip", args[i + 1]);
                i++;
            }
        }

        if (engine.process()) {
            System.out.println("DPI processing completed successfully");
        } else {
            System.out.println("DPI processing failed");
            System.exit(1);
        }
    }
}