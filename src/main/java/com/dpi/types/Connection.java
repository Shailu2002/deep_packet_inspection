package com.dpi.types;

import java.time.Instant;

public class Connection {
    private final FiveTuple tuple;
    private ConnectionState state;
    private AppType appType;
    private String sni;
    private long packetsIn, packetsOut, bytesIn, bytesOut;
    private Instant firstSeen, lastSeen;
    private PacketAction action;
    private boolean synSeen, synAckSeen, finSeen;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
        this.state = ConnectionState.NEW;
        this.appType = AppType.UNKNOWN;
        this.sni = "";
        this.action = PacketAction.FORWARD;
        this.firstSeen = Instant.now();
        this.lastSeen = Instant.now();
    }

    public FiveTuple getTuple() { return tuple; }
    public ConnectionState getState() { return state; }
    public void setState(ConnectionState state) { this.state = state; }
    public AppType getAppType() { return appType; }
    public void setAppType(AppType appType) { this.appType = appType; }
    public String getSni() { return sni; }
    public void setSni(String sni) { this.sni = sni != null ? sni : ""; }
    public long getPacketsIn() { return packetsIn; }
    public void incPacketsIn() { packetsIn++; }
    public long getPacketsOut() { return packetsOut; }
    public void incPacketsOut() { packetsOut++; }
    public long getBytesIn() { return bytesIn; }
    public void addBytesIn(long bytes) { bytesIn += bytes; }
    public long getBytesOut() { return bytesOut; }
    public void addBytesOut(long bytes) { bytesOut += bytes; }
    public Instant getFirstSeen() { return firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public void updateLastSeen() { lastSeen = Instant.now(); }
    public PacketAction getAction() { return action; }
    public void setAction(PacketAction action) { this.action = action; }
    public boolean isSynSeen() { return synSeen; }
    public void setSynSeen(boolean synSeen) { this.synSeen = synSeen; }
    public boolean isSynAckSeen() { return synAckSeen; }
    public void setSynAckSeen(boolean synAckSeen) { this.synAckSeen = synAckSeen; }
    public boolean isFinSeen() { return finSeen; }
    public void setFinSeen(boolean finSeen) { this.finSeen = finSeen; }
}