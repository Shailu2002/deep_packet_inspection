package com.dpi.threading;

import com.dpi.pcap.RawPacket;
import com.dpi.parser.ParsedPacket;
import com.dpi.types.FiveTuple;

public class RoutedPacket {
  public final RawPacket raw;
  public final ParsedPacket parsed;
  public final FiveTuple tuple;
  public final int hash;
  public final boolean sentinel;

  private RoutedPacket(RawPacket raw, ParsedPacket parsed, FiveTuple tuple, int hash, boolean sentinel) {
    this.raw = raw;
    this.parsed = parsed;
    this.tuple = tuple;
    this.hash = hash;
    this.sentinel = sentinel;
  }

  public static RoutedPacket of(RawPacket raw, ParsedPacket parsed, FiveTuple tuple) {
    int h = tuple.hashCode() & 0x7FFFFFFF;
    return new RoutedPacket(raw, parsed, tuple, h, false);
  }

  public static RoutedPacket sentinel() {
    return new RoutedPacket(null, null, null, -1, true);
  }
}