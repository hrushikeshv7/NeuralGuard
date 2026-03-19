import warnings; warnings.filterwarnings("ignore")
import os; os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, render_template_string, jsonify
import joblib, pandas as pd, threading
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
import sys; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app  = Flask(__name__)
clf  = joblib.load("models/classifier.pkl"); clf.verbose = 0
le   = joblib.load("models/label_encoder.pkl")
COLS = joblib.load("models/feature_cols.pkl")

state = {"total":0,"benign":0,"malicious":0,"blocked":[],"log":[],"malicious_ips":{}}

# ── Flow tracker ──
flows = defaultdict(lambda: {
    "ports":set(),"syn":0,"bytes":0,"pkts":0,
    "start":datetime.now().timestamp()
})

PRIVATE      = ("10.","192.168.","172.16.","127.","169.254.","224.","0.0.")
TRUSTED_DST  = {80,443,53,123,67,68,5000,8080,8443}
AUTH_PORTS   = {22,3389,21,23,5900}
DANGER_PORTS = {4444,6379,27017,9200,5555,1433}

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE)

def block_ip(ip):
    if ip not in state["blocked"]:
        state["blocked"].append(ip)
        # Actually block with iptables
        os.system(f"iptables -I INPUT -s {ip} -j DROP 2>/dev/null")
        os.system(f"iptables -I FORWARD -s {ip} -j DROP 2>/dev/null")
        print(f"🚫 ACTUALLY BLOCKED: {ip}")

def check_rules(src, dst, dst_port, flags, size, ttl):
    now = datetime.now().timestamp()
    f   = flows[src]
    elapsed = max(now - f["start"], 0.001)

    # ── Always update flow tracker first ──
    f["pkts"]  += 1
    f["bytes"] += size
    if dst_port: f["ports"].add(dst_port)
    if flags == 2: f["syn"] += 1

    # Reset flow every 60 seconds
    if elapsed > 60:
        flows[src] = {"ports":set(),"syn":0,"bytes":0,"pkts":0,"start":now}
        return "BENIGN", 0.90, "flow-reset"

    pkt_rate  = f["pkts"]  / elapsed
    byte_rate = f["bytes"] / elapsed
    syn_ratio = f["syn"]   / max(f["pkts"], 1)
    n_ports   = len(f["ports"])

    # ── RULE 1: Port scan — check BEFORE trusted port bypass ──
    # So even if attacker hits port 80/443, we still count the ports
    if n_ports >= 20 and pkt_rate > 5:
        return "MALICIOUS", min(0.99, 0.75+n_ports*0.008), \
               f"port-scan:{n_ports}ports"

    # ── RULE 2: SYN flood ──
    if syn_ratio > 0.90 and pkt_rate > 50:
       return "MALICIOUS", 0.98, f"syn-flood:{pkt_rate:.0f}pkt/s"

    # ── RULE 3: DDoS volume ──
    if byte_rate > 5_000_000:
        return "MALICIOUS", 0.97, f"ddos:{byte_rate/1000:.0f}KB/s"

    # ── RULE 4: Brute force on auth ports ──
    if dst_port in AUTH_PORTS and f["pkts"] > 50 and elapsed < 15:
        return "MALICIOUS", min(0.99, 0.80+f["pkts"]*0.003), \
               f"brute-force:port{dst_port}"

    # ── RULE 5: Known exploit ports (external only) ──
    if dst_port in DANGER_PORTS and not is_private(src):
        return "MALICIOUS", 0.88, f"exploit-port:{dst_port}"

    # ── RULE 6: Ghost TTL ──
    if ttl < 8:
        return "MALICIOUS", 0.85, f"ghost-ttl:{ttl}"

    # ── RULE 7: NULL scan ──
    if flags == 0 and n_ports >= 10 and pkt_rate > 5:
        return "MALICIOUS", 0.95, "null-scan"

    # ── RULE 8: XMAS scan ──
    if flags == 41 and n_ports >= 5:
        return "MALICIOUS", 0.95, "xmas-scan"

    # ── Trusted port = benign AFTER all attack checks pass ──
    if dst_port in TRUSTED_DST:
        return "BENIGN", 0.95, "trusted-port"

    return "BENIGN", 0.88, "clean"

def predict_packet(pkt):
    if not (IP in pkt): return
    try:
        src  = pkt[IP].src
        dst  = pkt[IP].dst
        ttl  = pkt[IP].ttl
        size = len(pkt)

        if src == "127.0.0.1" or dst == "127.0.0.1": return
          # ADD THIS 
       
        dst_port = 0
        src_port = 0
        flags    = 0
        if TCP in pkt:
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport
            flags    = int(pkt[TCP].flags)
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            src_port = pkt[UDP].sport

        if dst_port == 5000 or src_port == 5000: return

        lbl, prob, reason = check_rules(src, dst, dst_port, flags, size, ttl)

        state["total"] += 1
        entry = {
            "time":    datetime.now().strftime("%H:%M:%S"),
            "src": src, "dst": dst,
            "label":   lbl,
            "conf":    round(prob*100, 1),
            "size":    size,
            "reason":  reason,
            "blocked": False
        }

        if lbl == "MALICIOUS":
            state["malicious"] += 1
            state["malicious_ips"][src] = state["malicious_ips"].get(src,0) + 1
            block_ip(src)
            entry["blocked"] = True
        else:
            state["benign"] += 1

        state["log"].insert(0, entry)
        state["log"] = state["log"][:100]
    except Exception as e:
        print(f"ERR: {e}")

HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta http-equiv="refresh" content="5">
<title>NeuralGuard</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
:root{--bg:#04050f;--panel:#080d1a;--border:#0ff2;--cyan:#00ffe7;--pink:#ff2d78;--purple:#9b5de5;--yellow:#f9c74f;--text:#c8d8f0;--dim:#4a5a7a;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;min-height:100vh;}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,255,231,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,231,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.06) 2px,rgba(0,0,0,0.06) 4px);pointer-events:none;z-index:0;}
.wrap{position:relative;z-index:1;padding:24px 32px;max-width:1400px;margin:0 auto;}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;padding-bottom:16px;border-bottom:1px solid var(--border);}
.logo{display:flex;align-items:center;gap:16px;}
.logo-hex{width:48px;height:48px;background:linear-gradient(135deg,var(--cyan),var(--purple));clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:20px;animation:hpulse 2s ease-in-out infinite;}
@keyframes hpulse{0%,100%{box-shadow:0 0 20px var(--cyan);}50%{box-shadow:0 0 40px var(--cyan),0 0 80px var(--purple);}}
.logo-text h1{font-family:'Orbitron',monospace;font-size:22px;font-weight:900;background:linear-gradient(90deg,var(--cyan),var(--purple),var(--pink));-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:3px;}
.logo-text p{font-size:11px;color:var(--dim);letter-spacing:4px;font-family:'Share Tech Mono',monospace;}
.sbar{display:flex;align-items:center;gap:8px;font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--cyan);}
.dot{width:8px;height:8px;border-radius:50%;background:var(--cyan);animation:blink 1s infinite;box-shadow:0 0 8px var(--cyan);}
@keyframes blink{50%{opacity:0.2;}}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:20px;position:relative;overflow:hidden;transition:transform 0.2s;}
.card:hover{transform:translateY(-2px);}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
.ct::before{background:linear-gradient(90deg,var(--purple),var(--cyan));}
.cg::before{background:linear-gradient(90deg,var(--cyan),#00ff88);}
.cm::before{background:linear-gradient(90deg,var(--pink),var(--yellow));}
.cb::before{background:linear-gradient(90deg,var(--yellow),var(--pink));}
.cl{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:3px;color:var(--dim);margin-bottom:8px;}
.cv{font-family:'Orbitron',monospace;font-size:38px;font-weight:900;line-height:1;margin-bottom:10px;}
.ct .cv{color:var(--purple);text-shadow:0 0 20px var(--purple);}
.cg .cv{color:var(--cyan);text-shadow:0 0 20px var(--cyan);}
.cm .cv{color:var(--pink);text-shadow:0 0 20px var(--pink);animation:flkr 3s infinite;}
.cb .cv{color:var(--yellow);text-shadow:0 0 20px var(--yellow);}
@keyframes flkr{0%,100%{opacity:1;}93%{opacity:0.3;}96%{opacity:0.5;}}
.cc{position:absolute;bottom:12px;right:14px;font-size:32px;opacity:0.1;}
.vbtn{display:inline-flex;align-items:center;gap:6px;padding:5px 14px;background:transparent;border:1px solid var(--border);border-radius:2px;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;cursor:pointer;transition:all 0.2s;}
.vbtn:hover{border-color:var(--cyan);color:var(--cyan);box-shadow:0 0 12px rgba(0,255,231,0.15);}
.vbtn-r:hover{border-color:var(--pink);color:var(--pink);box-shadow:0 0 12px rgba(255,45,120,0.15);}
.tw{background:var(--panel);border:1px solid var(--border);border-radius:4px;overflow:hidden;}
.th2{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid var(--border);}
.tt{font-family:'Orbitron',monospace;font-size:12px;letter-spacing:3px;color:var(--cyan);}
.live{display:flex;align-items:center;gap:6px;font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--pink);letter-spacing:2px;}
table{width:100%;border-collapse:collapse;}
th{padding:10px 16px;text-align:left;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--dim);background:rgba(0,0,0,0.3);border-bottom:1px solid var(--border);}
td{padding:9px 16px;font-size:13px;font-weight:600;border-bottom:1px solid rgba(255,255,255,0.03);}
tr:hover td{background:rgba(0,255,231,0.02);}
.tag{display:inline-block;padding:2px 10px;font-family:'Orbitron',monospace;font-size:9px;letter-spacing:2px;border-radius:2px;font-weight:700;}
.BENIGN{background:rgba(0,255,231,0.08);color:var(--cyan);border:1px solid rgba(0,255,231,0.3);}
.MALICIOUS{background:rgba(255,45,120,0.1);color:var(--pink);border:1px solid rgba(255,45,120,0.4);animation:mp 1.5s ease-in-out infinite;}
@keyframes mp{0%,100%{box-shadow:0 0 8px rgba(255,45,120,0.2);}50%{box-shadow:0 0 18px rgba(255,45,120,0.5);}}
.ip{font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--text);}
.tm{font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--purple);}
.rs{font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--yellow);}
.ch{font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--pink);font-weight:bold;}
.cl2{font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--dim);}
.by{color:var(--pink);font-family:'Share Tech Mono',monospace;font-size:12px;}
.bn{color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:12px;}
.ov{display:none;position:fixed;inset:0;background:rgba(4,5,15,0.93);z-index:100;align-items:center;justify-content:center;backdrop-filter:blur(4px);}
.ov.on{display:flex;}
.mod{background:var(--panel);border:1px solid var(--border);border-radius:4px;width:600px;max-height:80vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 0 60px rgba(0,255,231,0.1);animation:mi 0.2s ease;}
@keyframes mi{from{opacity:0;transform:scale(0.96) translateY(10px);}to{opacity:1;transform:scale(1) translateY(0);}}
.mh{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.3);}
.mt{font-family:'Orbitron',monospace;font-size:13px;letter-spacing:3px;color:var(--cyan);}
.mt.r{color:var(--pink);}
.mb{overflow-y:auto;padding:16px 20px;flex:1;}
.mb::-webkit-scrollbar{width:3px;}
.mb::-webkit-scrollbar-thumb{background:var(--border);}
.xb{background:none;border:1px solid var(--border);color:var(--dim);padding:4px 12px;cursor:pointer;font-family:'Share Tech Mono',monospace;font-size:11px;border-radius:2px;transition:all 0.2s;}
.xb:hover{border-color:var(--pink);color:var(--pink);}
.ir{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);}
.ir:last-child{border-bottom:none;}
.ia{font-family:'Share Tech Mono',monospace;font-size:14px;color:var(--text);}
.ic{font-family:'Orbitron',monospace;font-size:11px;padding:2px 10px;background:rgba(255,45,120,0.1);color:var(--pink);border:1px solid rgba(255,45,120,0.3);border-radius:2px;}
.ib{font-family:'Orbitron',monospace;font-size:9px;padding:2px 10px;background:rgba(249,199,79,0.1);color:var(--yellow);border:1px solid rgba(249,199,79,0.3);border-radius:2px;letter-spacing:2px;}
.em{text-align:center;padding:40px;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px;}
</style></head>
<body><div class="wrap">
<header>
  <div class="logo">
    <div class="logo-hex">⬡</div>
    <div class="logo-text">
      <h1>NEURALGUARD</h1>
      <p>AI-POWERED FIREWALL DEFENSE SYSTEM</p>
    </div>
  </div>
  <div class="sbar"><div class="dot"></div>SYSTEM ONLINE &nbsp;|&nbsp; MONITORING ACTIVE</div>
</header>
<div class="cards">
  <div class="card ct"><div class="cl">TOTAL PACKETS</div><div class="cv">{{s.total}}</div><div class="cc">◈</div></div>
  <div class="card cg"><div class="cl">BENIGN TRAFFIC</div><div class="cv">{{s.benign}}</div><div class="cc">◎</div></div>
  <div class="card cm">
    <div class="cl">THREATS DETECTED</div><div class="cv">{{s.malicious}}</div>
    <button class="vbtn vbtn-r" onclick="openModal('mal')">⚡ VIEW LIST</button>
    <div class="cc">◬</div>
  </div>
  <div class="card cb">
    <div class="cl">BLOCKED IPs</div><div class="cv">{{s.blocked|length}}</div>
    <button class="vbtn" onclick="openModal('blk')">⬡ VIEW LIST</button>
    <div class="cc">◆</div>
  </div>
</div>
<div class="tw">
  <div class="th2">
    <span class="tt">LIVE TRAFFIC MONITOR</span>
    <span class="live"><span class="dot"></span>REAL-TIME FEED</span>
  </div>
  <table>
    <thead><tr>
      <th>TIME</th><th>SOURCE IP</th><th>DESTINATION</th>
      <th>STATUS</th><th>CONFIDENCE</th><th>REASON</th><th>ACTION</th>
    </tr></thead>
    <tbody>
    {%for e in log%}<tr>
      <td><span class="tm">{{e.time}}</span></td>
      <td><span class="ip">{{e.src}}</span></td>
      <td><span class="ip">{{e.dst}}</span></td>
      <td><span class="tag {{e.label}}">{{e.label}}</span></td>
      <td><span class="{{'ch' if e.conf>70 else 'cl2'}}">{{e.conf}}%</span></td>
      <td><span class="rs">{{e.reason}}</span></td>
      <td>{%if e.blocked%}<span class="by">🚫 BLOCKED</span>{%else%}<span class="bn">✓ ALLOWED</span>{%endif%}</td>
    </tr>{%endfor%}
    </tbody>
  </table>
</div></div>

<div class="ov" id="modal-mal">
  <div class="mod">
    <div class="mh"><span class="mt r">⚡ MALICIOUS IP RECORDS</span><button class="xb" onclick="closeModal('mal')">✕ CLOSE</button></div>
    <div class="mb">
      {%if s.malicious_ips%}
        {%for ip,cnt in s.malicious_ips.items()%}
        <div class="ir"><span class="ia">{{ip}}</span><span class="ic">{{cnt}} ATTACKS</span></div>
        {%endfor%}
      {%else%}<div class="em">// NO THREATS DETECTED YET</div>{%endif%}
    </div>
  </div>
</div>

<div class="ov" id="modal-blk">
  <div class="mod">
    <div class="mh"><span class="mt">⬡ BLOCKED IP REGISTRY</span><button class="xb" onclick="closeModal('blk')">✕ CLOSE</button></div>
    <div class="mb">
      {%if s.blocked%}
        {%for ip in s.blocked%}
        <div class="ir"><span class="ia">{{ip}}</span><span class="ib">BLOCKED</span></div>
        {%endfor%}
      {%else%}<div class="em">// NO IPs BLOCKED YET</div>{%endif%}
    </div>
  </div>
</div>

<script>
function openModal(t){document.getElementById('modal-'+t).classList.add('on');}
function closeModal(t){document.getElementById('modal-'+t).classList.remove('on');}
document.querySelectorAll('.ov').forEach(el=>{
  el.addEventListener('click',function(e){if(e.target===this)this.classList.remove('on');});
});
</script></body></html>"""

@app.route("/")
def index(): return render_template_string(HTML, s=state, log=state["log"])

@app.route("/api")
def api(): return jsonify(state)

if __name__ == "__main__":
    print("🚀 NeuralGuard starting...")
    t = threading.Thread(
        target=lambda: sniff(iface="wlan0", prn=predict_packet, store=False, filter="ip"),
        daemon=True)
    t.start()
    print("🌐 Dashboard → http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
