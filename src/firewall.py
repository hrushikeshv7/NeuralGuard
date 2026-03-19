import subprocess

def block_ip(ip: str):
    result = subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    return result.returncode == 0

def unblock_ip(ip: str):
    result = subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    return result.returncode == 0

def list_blocked():
    result = subprocess.run(
        ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    print(result.stdout)

def clear_all_blocks():
    subprocess.run(["iptables", "-F", "INPUT"],
                   capture_output=True)
    print("✅ All blocks cleared")

if __name__ == "__main__":
    print("🔥 Current firewall rules:")
    list_blocked()
