package com.dpi.engine;

import com.dpi.types.AppType;
import java.util.*;

public class RuleManager {
    private Set<Long> blockedIPs;
    private Set<AppType> blockedApps;
    private Set<String> blockedDomains;

    public RuleManager() {
        this.blockedIPs = new HashSet<>();
        this.blockedApps = new HashSet<>();
        this.blockedDomains = new HashSet<>();
    }

    public void addRule(String ruleType, String value) {
        switch (ruleType.toLowerCase()) {
            case "ip":
                blockedIPs.add(ipToLong(value));
                System.out.println("[Rules] Blocked IP: " + value);
                break;
            case "app":
                blockedApps.add(AppType.valueOf(value.toUpperCase()));
                System.out.println("[Rules] Blocked app: " + value);
                break;
            case "domain":
                blockedDomains.add(value.toLowerCase());
                System.out.println("[Rules] Blocked domain: " + value);
                break;
        }
    }

    public boolean isBlocked(long srcIp, AppType appType, String sni) {
        if (blockedIPs.contains(srcIp)) return true;
        if (blockedApps.contains(appType)) return true;
        String lowerSni = sni.toLowerCase();
        for (String domain : blockedDomains) {
            if (lowerSni.contains(domain)) return true;
        }
        return false;
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i]) << (i * 8));
        }
        return result;
    }
}