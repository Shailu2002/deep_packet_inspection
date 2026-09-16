package com.dpi.threading;

import java.util.concurrent.*;

public class ThreadSafeQueue<T> {
    private final BlockingQueue<T> queue;

    public ThreadSafeQueue(int capacity) {
        this.queue = new LinkedBlockingQueue<>(capacity);
    }

    public void push(T item) throws InterruptedException {
        queue.put(item);
    }

    public T pop() throws InterruptedException {
        return queue.take();
    }

    public boolean offerIfSpace(T item) {
        return queue.offer(item);
    }

    public int size() {
        return queue.size();
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public void clear() {
        queue.clear();
    }
}