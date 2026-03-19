from scapy.all import IP, TCP, UDP, ICMP
from datetime import datetime

flow_tracker = {}

def extract_features(pkt):
    f = {
        "protocol": 0, "src_port": 0, "dst_port": 0,
        "pkt_size": len(pkt), "ttl": 0, "tcp_flags": 0,
        "is_tcp": 0, "is_udp": 0, "is_icmp": 0,
        "flow_count": 1, "byte_rate": 0
    }
    if IP in pkt:
        f["protocol"] = pkt[IP].proto
        f["ttl"]      = pkt[IP].ttl
        src = pkt[IP].src
        now = datetime.now().timestamp()
        if src not in flow_tracker:
            flow_tracker[src] = {"count":0,"bytes":0,"start":now}
        flow_tracker[src]["count"] += 1
        flow_tracker[src]["bytes"] += len(pkt)
        elapsed = now - flow_tracker[src]["start"]
        f["flow_count"] = flow_tracker[src]["count"]
        f["byte_rate"]  = flow_tracker[src]["bytes"] / elapsed if elapsed > 0 else len(pkt)*1000
        if elapsed > 60:
            flow_tracker[src] = {"count":0,"bytes":0,"start":now}
    if TCP in pkt:
        f["src_port"]  = pkt[TCP].sport
        f["dst_port"]  = pkt[TCP].dport
        f["tcp_flags"] = int(pkt[TCP].flags)
        f["is_tcp"]    = 1
    elif UDP in pkt:
        f["src_port"] = pkt[UDP].sport
        f["dst_port"] = pkt[UDP].dport
        f["is_udp"]   = 1
    elif ICMP in pkt:
        f["is_icmp"]  = 1
    return f
