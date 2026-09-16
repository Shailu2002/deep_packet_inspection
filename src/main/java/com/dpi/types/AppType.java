package com.dpi.types;

public enum AppType {
    UNKNOWN(0), HTTP(1), HTTPS(2), DNS(3), TLS(4), QUIC(5),
    GOOGLE(6), FACEBOOK(7), YOUTUBE(8), TWITTER(9), INSTAGRAM(10), NETFLIX(11),
    AMAZON(12), MICROSOFT(13), APPLE(14), WHATSAPP(15), TELEGRAM(16), TIKTOK(17),
    SPOTIFY(18), ZOOM(19), DISCORD(20), GITHUB(21), CLOUDFLARE(22);

    private final int value;
    AppType(int value) { this.value = value; }
    public int getValue() { return value; }

    public static String toDisplayString(AppType type) {
        switch (type) {
            case UNKNOWN: return "Unknown";
            case HTTP: return "HTTP";
            case HTTPS: return "HTTPS";
            case DNS: return "DNS";
            case TLS: return "TLS";
            case QUIC: return "QUIC";
            case GOOGLE: return "Google";
            case FACEBOOK: return "Facebook";
            case YOUTUBE: return "YouTube";
            case TWITTER: return "Twitter/X";
            case INSTAGRAM: return "Instagram";
            case NETFLIX: return "Netflix";
            case AMAZON: return "Amazon";
            case MICROSOFT: return "Microsoft";
            case APPLE: return "Apple";
            case WHATSAPP: return "WhatsApp";
            case TELEGRAM: return "Telegram";
            case TIKTOK: return "TikTok";
            case SPOTIFY: return "Spotify";
            case ZOOM: return "Zoom";
            case DISCORD: return "Discord";
            case GITHUB: return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default: return "Unknown";
        }
    }

    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String lower = sni.toLowerCase();
        
        if (lower.contains("youtube") || lower.contains("ytimg")) return YOUTUBE;
        if (lower.contains("facebook") || lower.contains("fbcdn")) return FACEBOOK;
        if (lower.contains("google") || lower.contains("googleapis")) return GOOGLE;
        if (lower.contains("netflix")) return NETFLIX;
        if (lower.contains("amazon") || lower.contains("amazonaws")) return AMAZON;
        if (lower.contains("microsoft") || lower.contains("outlook")) return MICROSOFT;
        if (lower.contains("apple") || lower.contains("icloud")) return APPLE;
        if (lower.contains("instagram")) return INSTAGRAM;
        if (lower.contains("twitter") || lower.contains("twimg")) return TWITTER;
        if (lower.contains("telegram")) return TELEGRAM;
        if (lower.contains("tiktok") || lower.contains("bytedance")) return TIKTOK;
        if (lower.contains("spotify")) return SPOTIFY;
        if (lower.contains("zoom")) return ZOOM;
        if (lower.contains("discord")) return DISCORD;
        if (lower.contains("github")) return GITHUB;
        if (lower.contains("cloudflare")) return CLOUDFLARE;
        if (lower.contains("whatsapp")) return WHATSAPP;
        
        return HTTPS;
    }
}