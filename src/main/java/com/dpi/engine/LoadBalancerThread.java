package com.dpi.engine;

import com.dpi.threading.RoutedPacket;
import java.util.concurrent.BlockingQueue;

public class LoadBalancerThread implements Runnable {
    private final String name;
    private final int lbIndex;
    private final BlockingQueue<RoutedPacket> inputQueue;
    private final BlockingQueue<RoutedPacket>[] ownWorkerQueues;
    private final int numLoadBalancers;
    private final int workersPerLb;

    public LoadBalancerThread(String name,
            int lbIndex,
            BlockingQueue<RoutedPacket> inputQueue,
            BlockingQueue<RoutedPacket>[] ownWorkerQueues,
            int numLoadBalancers,
            int workersPerLb) {
        this.name = name;
        this.lbIndex = lbIndex;
        this.inputQueue = inputQueue;
        this.ownWorkerQueues = ownWorkerQueues;
        this.numLoadBalancers = numLoadBalancers;
        this.workersPerLb = workersPerLb;
    }

    @Override
    public void run() {
        Thread.currentThread().setName(name);
        try {
            while (true) {
                RoutedPacket packet = inputQueue.take();

                if (packet.sentinel) {
                    for (BlockingQueue<RoutedPacket> q : ownWorkerQueues) {
                        q.put(RoutedPacket.sentinel());
                    }
                    break;
                }

                int subIndex = (packet.hash / numLoadBalancers) % workersPerLb;
                int globalWorkerIndex = lbIndex * workersPerLb + subIndex;

                ownWorkerQueues[subIndex].put(packet);

                System.out.printf("[%s] flow-hash=%d -> Worker-%d (local slot %d)%n",
                        name, packet.hash, globalWorkerIndex, subIndex);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println(name + " interrupted");
        }
    }
}