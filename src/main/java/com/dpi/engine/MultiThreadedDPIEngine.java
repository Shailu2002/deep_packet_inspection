package com.dpi.engine;

import com.dpi.pcap.*;
import com.dpi.parser.*;
import com.dpi.threading.RoutedPacket;
import com.dpi.types.*;
import java.util.*;
import java.util.concurrent.*;

public class MultiThreadedDPIEngine {
    private static final int NUM_LOAD_BALANCERS = 2;

    private PcapReader pcapReader;
    private RuleManager ruleManager;
    private Map<FiveTuple, Connection> flows;
    private DPIStats stats;
    private String inputFile;
    private final int workersPerLb;
    private final int totalWorkers;

    private BlockingQueue<RoutedPacket>[] lbInputQueues;
    private BlockingQueue<RoutedPacket>[] workerQueues;

    private ExecutorService executorService;
    private CountDownLatch workerCompletionLatch;

    @SuppressWarnings("unchecked")
    public MultiThreadedDPIEngine(String inputFile, String outputFile, int requestedWorkers) {
        this.inputFile = inputFile;
        this.pcapReader = new PcapReader();
        this.ruleManager = new RuleManager();
        this.flows = new ConcurrentHashMap<>();
        this.stats = new DPIStats();

        int workers = requestedWorkers > 0 ? requestedWorkers : Runtime.getRuntime().availableProcessors();
        if (workers < NUM_LOAD_BALANCERS) {
            workers = NUM_LOAD_BALANCERS;
        }
        if (workers % NUM_LOAD_BALANCERS != 0) {
            workers += (NUM_LOAD_BALANCERS - (workers % NUM_LOAD_BALANCERS));
        }
        this.workersPerLb = workers / NUM_LOAD_BALANCERS;
        this.totalWorkers = workers;

        this.lbInputQueues = new BlockingQueue[NUM_LOAD_BALANCERS];
        for (int i = 0; i < NUM_LOAD_BALANCERS; i++) {
            this.lbInputQueues[i] = new LinkedBlockingQueue<>(500);
        }

        this.workerQueues = new BlockingQueue[totalWorkers];
        for (int i = 0; i < totalWorkers; i++) {
            this.workerQueues[i] = new LinkedBlockingQueue<>(100);
        }

        this.workerCompletionLatch = new CountDownLatch(totalWorkers);
        this.executorService = Executors.newFixedThreadPool(totalWorkers + NUM_LOAD_BALANCERS);
    }

    public boolean process() {
        try {
            if (!pcapReader.open(inputFile)) {
                System.err.println("Failed to open PCAP file");
                return false;
            }

            System.out.println("Starting Multi-Threaded DPI Processing (2-tier hierarchical): "
                    + NUM_LOAD_BALANCERS + " load balancers x " + workersPerLb
                    + " workers = " + totalWorkers + " total worker threads...");

            for (int lb = 0; lb < NUM_LOAD_BALANCERS; lb++) {
                BlockingQueue<RoutedPacket>[] slice = Arrays.copyOfRange(
                        workerQueues, lb * workersPerLb, (lb + 1) * workersPerLb);
                executorService.submit(new LoadBalancerThread(
                        "LB-" + lb, lb, lbInputQueues[lb], slice, NUM_LOAD_BALANCERS, workersPerLb));
            }

            for (int w = 0; w < totalWorkers; w++) {
                executorService.submit(new FastPathThread(
                        "Worker-" + w, workerQueues[w], flows, ruleManager, stats, workerCompletionLatch));
            }

            int packetCount = 0;
            RawPacket rawPacket = new RawPacket();

            while (pcapReader.readNextPacket(rawPacket)) {
                stats.incTotalPackets();
                stats.addTotalBytes(rawPacket.data.length);

                RawPacket cloned = new RawPacket();
                cloned.header = rawPacket.header;
                cloned.data = rawPacket.data.clone();

                ParsedPacket parsed = new ParsedPacket();
                if (!PacketParser.parse(cloned, parsed) || !parsed.hasIP) {
                    continue;
                }

                if (parsed.hasTCP) {
                    stats.incTcpPackets();
                } else if (parsed.hasUDP) {
                    stats.incUdpPackets();
                }

                FiveTuple tuple = buildFiveTuple(parsed);
                RoutedPacket routed = RoutedPacket.of(cloned, parsed, tuple);
                int lbIndex = routed.hash % NUM_LOAD_BALANCERS;

                try {
                    lbInputQueues[lbIndex].put(routed);
                    packetCount++;
                    if (packetCount % 1000 == 0) {
                        System.out.println("Routed " + packetCount + " packets to load balancers");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            pcapReader.close();

            System.out.println("All packets routed (" + packetCount + "). Waiting for processing...");
            for (int lb = 0; lb < NUM_LOAD_BALANCERS; lb++) {
                try {
                    lbInputQueues[lb].put(RoutedPacket.sentinel());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            boolean completed = workerCompletionLatch.await(2, TimeUnit.MINUTES);
            if (!completed) {
                System.err.println("Workers did not complete in time");
                return false;
            }

            executorService.shutdown();
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                System.err.println("Executor did not terminate in time");
                executorService.shutdownNow();
                return false;
            }

            generateReport();
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private FiveTuple buildFiveTuple(ParsedPacket parsed) {
        long srcIp = parseIP(parsed.srcIp);
        long dstIp = parseIP(parsed.destIp);
        return new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);
    }

    private long parseIP(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i]) << (i * 8));
        }
        return result;
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
                .map(Connection::getSni)
                .distinct()
                .sorted()
                .forEach(sni -> {
                    AppType appType = flows.values().stream()
                            .filter(c -> c.getSni().equals(sni))
                            .findFirst()
                            .map(Connection::getAppType)
                            .orElse(AppType.UNKNOWN);
                    System.out.printf("  - %s -> %s%n", sni, AppType.toDisplayString(appType));
                });
    }

    private String padValue(long value) {
        return String.format("%-30d", value);
    }

    public void addBlockRule(String type, String value) {
        ruleManager.addRule(type, value);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println(
                    "Usage: java MultiThreadedDPIEngine <input.pcap> <output.pcap> [--threads N] [--block-app APP] [--block-domain DOMAIN]");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];
        int numThreads = Runtime.getRuntime().availableProcessors();

        for (int i = 2; i < args.length; i++) {
            if (args[i].equals("--threads") && i + 1 < args.length) {
                try {
                    numThreads = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid thread count");
                }
            }
        }

        MultiThreadedDPIEngine engine = new MultiThreadedDPIEngine(inputFile, outputFile, numThreads);

        for (int i = 2; i < args.length; i++) {
            if (args[i].equals("--block-app") && i + 1 < args.length) {
                engine.addBlockRule("app", args[++i]);
            } else if (args[i].equals("--block-domain") && i + 1 < args.length) {
                engine.addBlockRule("domain", args[++i]);
            } else if (args[i].equals("--block-ip") && i + 1 < args.length) {
                engine.addBlockRule("ip", args[++i]);
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