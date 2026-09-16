package com.dpi.engine;
import com.dpi.pcap.RawPacket;
import java.util.concurrent.BlockingQueue;

/**
 * LoadBalancerThread distributes incoming packets across multiple worker
 * threads
 * using a round-robin load balancing strategy.
 */
public class LoadBalancerThread implements Runnable {
    private final BlockingQueue<RawPacket> inputQueue;
    private final BlockingQueue<RawPacket>[] workerQueues;
    private final int numWorkers;
    private int currentWorker = 0;

    public LoadBalancerThread(BlockingQueue<RawPacket> inputQueue,
            BlockingQueue<RawPacket>[] workerQueues,
            int numWorkers) {
        this.inputQueue = inputQueue;
        this.workerQueues = workerQueues;
        this.numWorkers = numWorkers;
    }

    @Override
    public void run() {
        try {
            int packetNumber = 0;
            while (true) {
                RawPacket packet = inputQueue.take();

                // Check for sentinel value (empty data array)
                if (packet.data.length == 0) {
                    // Distribute sentinel to all workers to signal end
                    for (BlockingQueue<RawPacket> queue : workerQueues) {
                        RawPacket sentinel = new RawPacket();
                        sentinel.data = new byte[0];
                        queue.put(sentinel);
                    }
                    break;
                }

                packetNumber++;

                // Terminal log: clearly shows which worker gets the packet
                System.out.printf("[LOAD BALANCER] Packet #%02d -> Dispatched to FastPathWorker-%d (Round-Robin)\n",
                        packetNumber, currentWorker);

                // Round-robin distribution
                workerQueues[currentWorker].put(packet);
                currentWorker = (currentWorker + 1) % numWorkers;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("LoadBalancerThread interrupted");
        }
    }
}