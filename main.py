import subprocess
import time
import sys
import os

def start_services():
    print("🚀 Starting NIDS Dashboard and Background Monitor...")

    if os.path.exists("live_predictions.csv"):
        print("Clearing old live_predictions.csv...")
        os.remove("live_predictions.csv")

    # Start Network Monitor Background Process
    monitor_process = subprocess.Popen(["python", "network_monitor.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Network monitor started (PID: {monitor_process.pid})")

    # Start Streamlit Dashboard
    dashboard_process = subprocess.Popen(["streamlit", "run", "dashboard.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Streamlit dashboard started (PID: {dashboard_process.pid})")
    print("\n✅ Setup complete! Go to http://localhost:8501 in your browser to view the dashboard.\n")

    try:
        # Keep launcher running until user stops it
        while True:
            time.sleep(1)
            # Check if processes crashed
            if monitor_process.poll() is not None:
                print(f"Error: Network monitor crashed with code {monitor_process.returncode}")
                break
            if dashboard_process.poll() is not None:
                print(f"Error: Dashboard crashed with code {dashboard_process.returncode}")
                break
    except KeyboardInterrupt:
        print("\nStopping all services...")
        monitor_process.terminate()
        dashboard_process.terminate()
        print("Services stopped.")

if __name__ == "__main__":
    start_services()
