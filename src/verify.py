import subprocess

print("\n" + "="*50)
print("  NeuralGuard — Phase 6 Verification Report")
print("="*50)

result = subprocess.run(
    ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
    capture_output=True, text=True
)

lines = [l for l in result.stdout.split('\n') if "DROP" in l]

print(f"\n✅ Total IPs blocked by iptables: {len(lines)}")
for l in lines:
    print(f"   🚫 {l.strip()}")

if len(lines) >= 1:
    print("\n🎯 PHASE 6 PASSED — Firewall is blocking real traffic!")
else:
    print("\n❌ PHASE 6 FAILED — No iptables rules found.")
    print("   Make sure dashboard is running with sudo")
print("="*50)
