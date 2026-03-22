import subprocess
import requests
import time
import os

DISCORD_WEBHOOK_URL = "" # Add your webhook here if needed

blocked_ips = set()

def block_ip(ip_address, reason="Multiple Malicious Flows"):
    if ip_address in blocked_ips or ip_address.startswith("10.") or ip_address.startswith("192.168."):
        # Don't block local subnets in a demo unless explicitly intended
        return False

    print(f"\n[NIPS] Active Mitigation Triggered! Blocking IP: {ip_address}")

    # OS Agnostic Blocking
    try:
        if os.name == 'nt': # Windows
            cmd = f'netsh advfirewall firewall add rule name="NIPS_BLOCK_{ip_address}" dir=in action=block remoteip={ip_address}'
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else: # Linux
            cmd = f'iptables -A INPUT -s {ip_address} -j DROP'
            subprocess.run(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        blocked_ips.add(ip_address)

        # Send Discord Alert
        if DISCORD_WEBHOOK_URL:
            payload = {
                "content": f"🚨 **NIPS Alert: IP Blocked!**\n**IP:** `{ip_address}`\n**Reason:** {reason}"
            }
            requests.post(DISCORD_WEBHOOK_URL, json=payload)

        return True
    except Exception as e:
        print(f"[NIPS Error] Failed to block {ip_address}: {e}")
        return False
