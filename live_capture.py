import sys
import time
import os
import signal
from scapy.all import sniff, wrpcap, IP, TCP, UDP

packets_list = []
capturing = True
STOP_FILE = ".stop_capture"

def signal_handler(sig, frame):
    global capturing
    print("\n[Capture] Stop signal received. Saving packets...")
    capturing = False

# Register signal handler for graceful shutdown on POSIX systems
signal.signal(signal.SIGINT, signal_handler)
try:
    signal.signal(signal.SIGTERM, signal_handler)
except AttributeError:
    pass # Windows might not support this

def check_stop_file():
    global capturing
    if os.path.exists(STOP_FILE):
        print("\n[Capture] Stop file detected. Saving packets...")
        capturing = False
        try:
            os.remove(STOP_FILE)
        except OSError:
            pass
        return True
    return False

def packet_callback(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        packets_list.append(packet)

def start_capture(output_file, duration=None, interface=None):
    global capturing
    print(f"[Capture] Starting live network capture to {output_file}...")
    start_time = time.time()

    # Ensure stop file is removed before starting
    if os.path.exists(STOP_FILE):
        try:
            os.remove(STOP_FILE)
        except OSError:
            pass

    # Check if we have root privileges (required for real sniffing on Linux/Mac, not always needed on Windows depending on npcap/winpcap)
    is_admin = False
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False

    if is_admin:
        try:
            while capturing:
                if check_stop_file():
                    break
                sniff(prn=packet_callback, store=False, filter="tcp or udp", timeout=1, iface=interface)
                if duration and (time.time() - start_time) > float(duration):
                    break
        except Exception as e:
            print(f"[Capture Error] Sniffing failed: {e}")
    else:
        print("[Capture Warning] Not running as Administrator/Root! Capture may fail or only see local packets.")
        try:
            while capturing:
                if check_stop_file():
                    break
                sniff(prn=packet_callback, store=False, filter="tcp or udp", timeout=1, iface=interface)
                if duration and (time.time() - start_time) > float(duration):
                    break
        except PermissionError:
            print("[Capture Error] Permission denied! You must run as Administrator to capture real network packets.")
        except Exception as e:
            print(f"[Capture Error] Sniffing failed: {e}")

    print(f"[Capture] Stopped. Saving {len(packets_list)} packets to {output_file}...")

    if len(packets_list) > 0:
        wrpcap(output_file, packets_list)
        print(f"[Capture] Successfully saved {output_file}.")
    else:
        print("[Capture] No packets captured! Creating empty pcap.")
        open(output_file, 'w').close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python live_capture.py <output_pcap_file> [duration] [interface]")
        sys.exit(1)

    output_pcap = sys.argv[1]
    duration = sys.argv[2] if len(sys.argv) > 2 else None
    iface = sys.argv[3] if len(sys.argv) > 3 else None

    start_capture(output_pcap, duration=duration, interface=iface)
