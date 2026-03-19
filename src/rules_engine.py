from datetime import datetime
from collections import defaultdict

# ── Flow tracking per IP ──
flows = defaultdict(lambda: {
    "ports": set(), "syn_count": 0, "bytes": 0,
    "packet_count": 0, "start": datetime.now().timestamp(),
    "last_seen": datetime.now().timestamp()
})

# ── Private IP ranges — NEVER malicious ──
PRIVATE = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "127.", "0.0.0.0",
    "169.254.", "224.", "255."
)

# ── Trusted services — never block ──
TRUSTED_PORTS_DST = {
    80, 443, 53, 123, 67, 68,   # HTTP, HTTPS, DNS, NTP, DHCP
    993, 995, 587, 465, 25,      # Email
    5000, 8080, 8443,            # Common dev ports
}

# ── Known malicious port targets ──
SUSPICIOUS_PORTS = {
    23,    # Telnet — nobody uses this legitimately
    1433,  # MSSQL brute force
    3306,  # MySQL exposed
    5900,  # VNC
    6379,  # Redis (often exploited)
    27017, # MongoDB (often exposed)
    4444,  # Metasploit default
    5555,  # Android ADB
    9200,  # Elasticsearch
}

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE)

def reset_flow(ip):
    now = datetime.now().timestamp()
    flows[ip] = {
        "ports": set(), "syn_count": 0, "bytes": 0,
        "packet_count": 0, "start": now, "last_seen": now
    }

def analyze(src, dst, proto, src_port, dst_port,
            flags, pkt_size, ttl):
    """
    Returns: (label, confidence, reason)
    Uses layered rules like real firewalls.
    """
    now = datetime.now().timestamp()

    # ── RULE 0: Never flag private-to-private ──
    if is_private(src) and is_private(dst):
        return "BENIGN", 0.99, "private-to-private"

    # ── RULE 1: Trusted destination ports = benign ──
    if dst_port in TRUSTED_PORTS_DST and flags in (16, 18, 24, 17):
        return "BENIGN", 0.95, "trusted-port"

    # ── Update flow tracker ──
    f = flows[src]
    elapsed = now - f["start"]
    f["packet_count"] += 1
    f["bytes"] += pkt_size
    f["last_seen"] = now
    if dst_port:
        f["ports"].add(dst_port)
    if flags == 2:  # SYN only
        f["syn_count"] += 1

    # Reset flow every 60 seconds
    if elapsed > 60:
        reset_flow(src)
        f = flows[src]
        elapsed = 1

    unique_ports  = len(f["ports"])
    pkt_rate      = f["packet_count"] / max(elapsed, 0.001)
    byte_rate     = f["bytes"] / max(elapsed, 0.001)
    syn_ratio     = f["syn_count"] / max(f["packet_count"], 1)

    # ── RULE 2: PORT SCAN ──
    # Hitting many different ports rapidly = scan
    if unique_ports >= 15 and pkt_rate > 5:
        conf = min(0.99, 0.75 + (unique_ports * 0.01))
        return "MALICIOUS", conf, f"port-scan:{unique_ports}-ports"

    # ── RULE 3: SYN FLOOD ──
    # High SYN ratio + high rate = flood
    if syn_ratio > 0.9 and pkt_rate > 100:
        return "MALICIOUS", 0.98, f"syn-flood:rate={pkt_rate:.0f}/s"

    # ── RULE 4: DDoS (volume) ──
    if byte_rate > 2_000_000 and pkt_rate > 500:
        return "MALICIOUS", 0.97, f"ddos:rate={byte_rate/1000:.0f}KB/s"

    # ── RULE 5: BRUTE FORCE ──
    # Repeated hits on auth ports
    AUTH_PORTS = {22, 3389, 21, 23, 5900}
    if dst_port in AUTH_PORTS and f["packet_count"] > 30 and elapsed < 30:
        conf = min(0.99, 0.75 + (f["packet_count"] * 0.005))
        return "MALICIOUS", conf, f"brute-force:port={dst_port}"

    # ── RULE 6: Known malicious port targets ──
    if dst_port in SUSPICIOUS_PORTS and not is_private(src):
        return "MALICIOUS", 0.85, f"suspicious-port:{dst_port}"

    # ── RULE 7: Ghost TTL (spoofed packets) ──
    if ttl < 10 and proto == 6:
        return "MALICIOUS", 0.82, f"low-ttl:{ttl}"

    # ── RULE 8: NULL / XMAS scan ──
    # flags == 0 is NULL scan, flags == 41 is XMAS
    if flags == 0 or flags == 41:
        return "MALICIOUS", 0.95, f"null-xmas-scan:flags={flags}"

    # ── RULE 9: Too many SYNs with no ACK (half-open) ──
    if f["syn_count"] > 50 and syn_ratio > 0.8:
        return "MALICIOUS", 0.90, f"half-open-scan:syns={f['syn_count']}"

    return "BENIGN", 0.85, "no-rules-triggered"
