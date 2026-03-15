import sys
import time
import os
import signal
from scapy.all import sniff, IP, TCP, UDP
from scapy.utils import PcapWriter

capturing = True
STOP_FILE = ".stop_capture"
pcap_writer = None
packets_captured = 0

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
        print("\n[Capture] Stop file detected. Stopping capture...")
        capturing = False
        try:
            os.remove(STOP_FILE)
        except OSError:
            pass
        return True
    return False

def packet_callback(packet):
    global packets_captured, pcap_writer
    if IP in packet and (TCP in packet or UDP in packet):
        if pcap_writer:
            pcap_writer.write(packet)
            packets_captured += 1

def start_capture(output_file, duration=None, interface=None):
    global capturing, pcap_writer, packets_captured
    print(f"[Capture] Starting live network capture to {output_file}...")
    start_time = time.time()

    # Ensure stop file is removed before starting
    if os.path.exists(STOP_FILE):
        try:
            os.remove(STOP_FILE)
        except OSError:
            pass

    pcap_writer = PcapWriter(output_file, append=True, sync=True)

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

    try:
        if is_admin:
            while capturing:
                if check_stop_file():
                    break
                sniff(prn=packet_callback, store=False, filter="tcp or udp", timeout=1, iface=interface)
                if duration and (time.time() - start_time) > float(duration):
                    break
        else:
            print("[Capture Warning] Not running as Administrator/Root! Capture may fail or only see local packets.")
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
    finally:
        if pcap_writer:
            pcap_writer.close()

    print(f"[Capture] Stopped. Successfully streamed {packets_captured} packets to {output_file}.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python live_capture.py <output_pcap_file> [duration] [interface]")
        sys.exit(1)

    output_pcap = sys.argv[1]
    duration = sys.argv[2] if len(sys.argv) > 2 else None
    iface = sys.argv[3] if len(sys.argv) > 3 else None

    start_capture(output_pcap, duration=duration, interface=iface)
