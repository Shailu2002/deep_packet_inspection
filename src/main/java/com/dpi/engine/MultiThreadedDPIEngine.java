package com.dpi.engine;
import com.dpi.pcap.*;
import com.dpi.parser.*;
import com.dpi.types.*;
import java.util.*;
import java.util.concurrent.*;

public class MultiThreadedDPIEngine {
    private PcapReader pcapReader;
    private RuleManager ruleManager;
    private Map<FiveTuple, Connection> flows;
    private DPIStats stats;
    private String inputFile;
    private int numThreads;

    // Thread-safe queues
    private BlockingQueue<RawPacket> inputQueue;
    private BlockingQueue<RawPacket>[] workerQueues;
    private ExecutorService executorService;
    private CountDownLatch workerCompletionLatch;

    @SuppressWarnings("unchecked")
    public MultiThreadedDPIEngine(String inputFile, String outputFile, int numThreads) {
        this.inputFile = inputFile;
        this.numThreads = numThreads > 0 ? numThreads : Runtime.getRuntime().availableProcessors();
        this.pcapReader = new PcapReader();
        this.ruleManager = new RuleManager();
        this.flows = new ConcurrentHashMap<>();
        this.stats = new DPIStats();

        // Initialize queues
        this.inputQueue = new LinkedBlockingQueue<>(1000);
        this.workerQueues = new BlockingQueue[this.numThreads];
        for (int i = 0; i < this.numThreads; i++) {
            this.workerQueues[i] = new LinkedBlockingQueue<>(100);
        }

        this.workerCompletionLatch = new CountDownLatch(this.numThreads);
        this.executorService = Executors.newFixedThreadPool(this.numThreads + 2);
    }

    public boolean process() {
        try {
            if (!pcapReader.open(inputFile)) {
                System.err.println("Failed to open PCAP file");
                return false;
            }

            System.out.println("Starting Multi-Threaded DPI Processing with " + numThreads + " worker threads...");

            // Start load balancer thread
            executorService.submit(new LoadBalancerThread(inputQueue, workerQueues, numThreads));

            // Start worker threads
            for (int i = 0; i < numThreads; i++) {
                executorService.submit(new FastPathThread(
                    workerQueues[i],
                    flows,
                    ruleManager,
                    stats,
                    workerCompletionLatch
                ));
            }

            // Reader thread - read packets and put in input queue
            int packetCount = 0;
            RawPacket rawPacket = new RawPacket();

            while (pcapReader.readNextPacket(rawPacket)) {
                // Clone the packet because it will be reused
                RawPacket cloned = new RawPacket();
                cloned.header = rawPacket.header;
                cloned.data = rawPacket.data.clone();

                try {
                    inputQueue.put(cloned);
                    packetCount++;
                    if (packetCount % 1000 == 0) {
                        System.out.println("Queued " + packetCount + " packets, Queue size: " + inputQueue.size());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            pcapReader.close();

            // Send sentinel values to signal end of input
            System.out.println("All packets queued (" + packetCount + "). Waiting for processing...");
            for (int i = 0; i < numThreads; i++) {
                try {
                    RawPacket sentinel = new RawPacket();
                    sentinel.data = new byte[0]; // Empty packet as sentinel
                    inputQueue.put(sentinel);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            // Wait for all workers to complete
            boolean completed = workerCompletionLatch.await(2, TimeUnit.MINUTES);
            if (!completed) {
                System.err.println("Workers did not complete in time");
                return false;
            }

            // Shutdown executor
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
            System.out.println("Usage: java MultiThreadedDPIEngine <input.pcap> <output.pcap> [--threads N] [--block-app APP] [--block-domain DOMAIN]");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];
        int numThreads = Runtime.getRuntime().availableProcessors();

        // Parse command line arguments
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

        // Parse blocking rules
        for (int i = 2; i < args.length; i++) {
            if (args[i].equals("--block-app") && i + 1 < args.length) {
                String app = args[++i];
                engine.addBlockRule("app", app);
            } else if (args[i].equals("--block-domain") && i + 1 < args.length) {
                String domain = args[++i];
                engine.addBlockRule("domain", domain);
            } else if (args[i].equals("--block-ip") && i + 1 < args.length) {
                String ip = args[++i];
                engine.addBlockRule("ip", ip);
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
