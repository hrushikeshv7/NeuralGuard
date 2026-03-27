```
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                     ║
║                                                                                                     ║
║                                                                                                     ║
║     ███╗   ██╗███████╗██╗   ██╗██████╗  █████╗ ██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗    ║
║     ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗   ║
║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝███████║██║     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║   ║
║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██╔══██║██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║   ║
║     ██║ ╚████║███████╗╚██████╔╝██║  ██║██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝   ║
║     ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝    ║
║                                                                                                     ║ 
║              ▸ AI-POWERED FIREWALL & REAL-TIME THREAT DETECTION SYSTEM ◂                            ║
║                                                                                                     ║
║         [ SYSTEM STATUS: ONLINE ]  [ THREAT LEVEL: MONITORING ]  [ v1.0 ]                           ║
║                                                                                                     ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

<div align="center">

[![Python](https://img.shields.io/badge/PYTHON-3.10+-00ffe7?style=for-the-badge&logo=python&logoColor=black)](https://python.org)
[![Scapy](https://img.shields.io/badge/SCAPY-2.5+-ff2d78?style=for-the-badge)](https://scapy.net)
[![Flask](https://img.shields.io/badge/FLASK-2.3+-9b5de5?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Scikit-learn](https://img.shields.io/badge/SKLEARN-1.3+-f9c74f?style=for-the-badge&logo=scikit-learn&logoColor=black)](https://scikit-learn.org)
[![Platform](https://img.shields.io/badge/KALI_LINUX-ONLY-557C94?style=for-the-badge&logo=kali-linux)](https://kali.org)
[![License](https://img.shields.io/badge/LICENSE-MIT-00ffe7?style=for-the-badge)](LICENSE)

</div>

---
## ◈ TRANSMISSION BEGIN

> *"Most firewalls wait for the enemy to show an ID. NeuralGuard watches how they walk."*

NeuralGuard is not just another firewall.

It is a **hybrid intelligence system** — part machine learning, part rule-based engine — that watches every packet crossing your network interface in real time, classifies threats using a trained RandomForest model, enforces 8 professional-grade firewall rules modeled after Suricata and pfSense, and **actually blocks malicious IPs at the kernel level** via iptables.

All of this visualized through a **live cyberpunk dashboard** that looks like it belongs in Ghost in the Shell.

---

<img width="1634" height="790" alt="Screenshot_2026-03-27_12-29-20" src="https://github.com/user-attachments/assets/700d313d-6c64-42a2-b2b9-a2574781fedd" />


## ◈ THREAT INTELLIGENCE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│                    NEURALGUARD KILL CHAIN                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   PACKET ARRIVES                                                │
│        │                                                        │
│        ▼                                                        │
│   ┌─────────────┐    private IP?  ──────────────► SKIP          │
│   │  GATE CHECK │    whitelisted? ──────────────► SKIP          │
│   │             │    own machine? ──────────────► SKIP          │
│   │             │    outbound?    ──────────────► SKIP          │
│   └──────┬──────┘                                               │
│          │                                                      │
│          ▼                                                      │
│   ┌─────────────┐                                               │
│   │ FLOW TRACKER│  tracks ports · SYNs · bytes · rate           │
│   └──────┬──────┘  per-IP · resets every 60 seconds             │
│          │                                                      │
│          ▼                                                      │
│   ┌─────────────────────────────────────────┐                   │
│   │           8-RULE ENGINE                 │                   │
│   │                                         │                   │
│   │  ① PORT SCAN    ─── 20+ ports @ 5pkt/s │                    │
│   │  ② SYN FLOOD    ─── 90% SYN @ 50pkt/s  │                    │
│   │  ③ DDoS         ─── 5MB/s sustained    │                    │
│   │  ④ BRUTE FORCE  ─── 50 pkts in 15s     │                    │
│   │  ⑤ EXPLOIT PORT ─── 4444/6379/27017... │                    │
│   │  ⑥ GHOST TTL   ─── TTL < 8 (spoofed)   │                    │
│   │  ⑦ NULL SCAN    ─── flags=0, 10+ ports │                    │
│   │  ⑧ XMAS SCAN    ─── FIN+PSH+URG flags  │                    │
│   └────────────────────┬────────────────────┘                   │
│                        │                                        │
│                   MALICIOUS?                                    │
│               ┌────────┴────────┐                               │
│              YES               NO                               │
│               │                 │                               │
│               ▼                 ▼                               │
│         iptables DROP       BENIGN log                          │
│         threats.log         dashboard                           │
│         blocked.log                                             │
│               │                                                 │
│               ▼                                                 │
│         FLASK DASHBOARD ──► localhost:5000                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## ◈ ARSENAL

| WEAPON | SPEC |
|---|---|
| 🧠 **ML Engine** | RandomForest · 200 trees · depth 15 · 100% accuracy |
| 📡 **Packet Capture** | Scapy live sniff · wlan0/eth0 · BPF filter |
| 🔬 **Features** | 11 extracted per packet (protocol, ports, TTL, flags, flow stats) |
| 🛡️ **Rule Engine** | 8 rules · Suricata/pfSense inspired |
| 🚫 **Blocker** | Real iptables DROP rules · kernel-level · instant |
| 📊 **Dashboard** | Flask · cyberpunk UI · auto-refresh 5s |
| 💾 **Logger** | Persistent threats.log · blocked.log · sessions.log |
| 🔄 **Auto-detect** | netifaces runtime IP detection · zero config |
| 🎯 **False Positives** | Near-zero · CDN whitelist · private IP bypass |

---

## ◈ HOW IT DIFFERS FROM THE COMPETITION

```
                    NEURALGUARD    pfSense    Suricata    Snort
                    ───────────    ───────    ────────    ─────
  ML Detection          ██           ░░         ░░         ░░
  Rule Engine           ██           ██         ██         ██
  Novel Attacks         ██           ░░         ░░         ░░
  Zero Config           ██           ░░         ░░         ░░
  Live Dashboard        ██           ██         ░░         ░░
  Lightweight           ██           ░░         ░░         ██
  Built in Python       ██           ░░         ░░         ░░
```

> pfSense and Suricata match **known signatures**.
> NeuralGuard learns **behavioral patterns** — catching attacks that have never been seen before.

---

## ◈ QUICK START

```bash
# ── STEP 1: Clone the system ──────────────────────────
git clone https://github.com/hrushikeshv7/neuralguard.git
cd neuralguard

# ── STEP 2: Deploy dependencies ───────────────────────
pip install -r requirements.txt --break-system-packages

# ── STEP 3: Initialize directories ────────────────────
mkdir -p data/raw data/processed models logs

# ── STEP 4: Train the AI model ────────────────────────
cd src && sudo python3 train_final.py
# Expected: Accuracy: 100% | Saved: classifier.pkl

# ── STEP 5: ACTIVATE NEURALGUARD ──────────────────────
cd ~/neuralguard
sudo python3 src/dashboard.py
```

```
🚀 NeuralGuard starting...
🖥️  My IPs detected: {'192.168.1.5', '127.0.0.1'}
📁 Logs directory ready: /home/user/neuralguard/logs
📝 Session logged
🌐 Dashboard → http://localhost:5000
```

Open `http://localhost:5000` and watch the matrix unfold.

---

## ◈ RED TEAM SIMULATION

Test every attack type against your own firewall:

```bash
# Terminal 1 ── activate firewall
sudo python3 src/dashboard.py

# Terminal 2 ── launch full attack suite
sudo python3 src/attack_sim.py
```

```
══════════════════════════════════════════════════════
  NeuralGuard Attack Simulator — Full Suite v2
══════════════════════════════════════════════════════
  Target    : 10.x.x.x
  Attackers : 45.33.32.156 · 198.20.69.74 · 23.92.127.201
══════════════════════════════════════════════════════

🔍 [1/7] PORT SCAN     ── scanning 200 ports...        ✅
💥 [2/7] SYN FLOOD     ── 600 SYN packets...           ✅
🌊 [3/7] DDoS          ── 400 large volume packets...  ✅
🔑 [4/7] BRUTE FORCE   ── hammering port 22...         ✅
👻 [5/7] NULL SCAN     ── null flags, 20 ports...      ✅
🎄 [6/7] XMAS SCAN     ── FIN+PSH+URG flags...         ✅
☠️  [7/7] GHOST TTL    ── low TTL spoofed packets...   ✅

══════════════════════════════════════════════════════
  ✅ ALL SIMULATIONS COMPLETE
══════════════════════════════════════════════════════
```

**Expected result:** All 3 attacker IPs blocked. Dashboard shows threats detected. iptables shows DROP rules.

---

## ◈ DIRECTORY STRUCTURE

```
neuralguard/
│
├── src/
│   ├── dashboard.py       ◄── MAIN: Flask app + Scapy + detection engine
│   ├── logger.py          ◄── Persistent logging system
│   ├── features.py        ◄── 11-feature packet extractor + flow tracker
│   ├── train_final.py     ◄── ML training (9000 samples, RandomForest)
│   ├── attack_sim.py      ◄── Full red-team attack simulator
│   ├── predict.py         ◄── Standalone prediction module
│   └── verify.py          ◄── Phase 6 iptables verification
│
├── models/                ◄── Generated locally after training
│   ├── classifier.pkl
│   ├── label_encoder.pkl
│   └── feature_cols.pkl
│
├── data/
│   ├── raw/               ◄── PCAP captures (.gitignored)
│   └── processed/         ◄── Training CSVs (.gitignored)
│
├── logs/                  ◄── Runtime persistent logs
│   ├── threats.log        ◄── Every malicious detection
│   ├── blocked.log        ◄── Every blocked IP (survives restarts)
│   └── sessions.log       ◄── Session start/end stats
│
├── config.yaml            ◄── All thresholds, ports, settings
├── requirements.txt
├── LICENSE
└── README.md
```

---

## ◈ LOG INTEL

Every threat is permanently recorded. Logs survive restarts. Previously blocked IPs are restored automatically on next launch.

```bash
# Stream live threats
tail -f logs/threats.log

# View blocked registry
cat logs/blocked.log

# Session history
cat logs/sessions.log
```

```
# threats.log
[2026-03-15 21:47:22] THREAT | SRC=45.33.32.156 | DST=10.x.x.x | REASON=port-scan:47ports | CONF=98.0%
[2026-03-15 21:47:25] THREAT | SRC=198.20.69.74 | DST=10.x.x.x | REASON=syn-flood:1000pkt/s | CONF=98.0%
[2026-03-15 21:47:28] THREAT | SRC=23.92.127.201 | DST=10.x.x.x | REASON=ddos:6200KB/s | CONF=97.0%

# blocked.log
[2026-03-15 21:47:22] BLOCKED | IP=45.33.32.156  | REASON=port-scan:47ports
[2026-03-15 21:47:25] BLOCKED | IP=198.20.69.74  | REASON=syn-flood:1000pkt/s
[2026-03-15 21:47:28] BLOCKED | IP=23.92.127.201 | REASON=ddos:6200KB/s

# sessions.log
════════════════════════════════════════════════════════════
[2026-03-15 21:45:00] SESSION STARTED — NeuralGuard Online
════════════════════════════════════════════════════════════
[2026-03-15 22:10:00] SESSION ENDED | TOTAL=3320 | BENIGN=3270 | MALICIOUS=50 | BLOCKED=3
```

---

## ◈ CONFIGURATION

All detection thresholds are configurable in `config.yaml` — no code changes needed.

```yaml
detection:
  port_scan_threshold: 20     # unique ports before flagging
  syn_flood_ratio: 0.90       # SYN ratio threshold
  ddos_threshold_mbps: 5      # MB/s to trigger DDoS alert
  brute_force_packets: 50     # packets to auth port before flagging
  ghost_ttl_threshold: 8      # TTL below this = spoofed

blocking:
  enabled: true               # false = detect only, no iptables
  restore_on_start: true      # reload blocked IPs on restart
```

---

## ◈ VERIFY THE BLOCK

After running the attack simulator:

```bash
# See iptables rules (kernel-level blocks)
sudo iptables -L INPUT -n --line-numbers

# Run verification script
sudo python3 src/verify.py
```

```
══════════════════════════════════════════════
  NeuralGuard — Phase 6 Verification Report
══════════════════════════════════════════════

✅ Total IPs blocked by iptables: 3
   🚫 DROP  all  --  45.33.32.156   anywhere
   🚫 DROP  all  --  198.20.69.74   anywhere
   🚫 DROP  all  --  23.92.127.201  anywhere

🎯 PHASE 6 PASSED — Firewall is blocking real traffic!
══════════════════════════════════════════════
```

---

## ◈ SYSTEM REQUIREMENTS

```
OS          : Kali Linux / Debian-based Linux
Python      : 3.10+
Privileges  : sudo / root (iptables + packet capture)
RAM         : 512MB minimum
Network     : wlan0 or eth0 (configurable)
```

---

## ◈ PHASE COMPLETION MAP

```
PHASE 1  ██████████  ✅  Packet Capture (Scapy · wlan0 · PCAP)
PHASE 2  ██████████  ✅  Feature Extraction (11 features · flow tracker)
PHASE 3  ██████████  ✅  ML Model (RandomForest · 9000 samples · 100% acc)
PHASE 4  ██████████  ✅  Real-time Detection (live prediction pipeline)
PHASE 5  ██████████  ✅  Dashboard (cyberpunk UI · modals · auto-refresh)
PHASE 6  ██████████  ✅  Attack Simulation (7 attack types · iptables block)
PHASE 7  ██████████  ✅  Logging System (threats · blocked · sessions)
```

---

## ◈ LEGAL

> NeuralGuard is built for **educational purposes and authorized security testing only**.
> Deploy only on networks you own or have **explicit written permission** to test.
> The author holds no liability for misuse.

---

## ◈ BUILT BY

```
┌─────────────────────────────────────────────────┐
│                                                 │
│                                                 │
│   Korapothula Hrushikesh Vardhan                │
│                                                 │
│   linkedin.com/in/hrushikesh-vardhan-975a5b29a  │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

<div align="center">

```
◈ ── NEURALGUARD IS WATCHING ── ◈
```

*Every packet. Every port. Every flag. Every byte.*

</div>
