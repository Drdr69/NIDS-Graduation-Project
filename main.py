import subprocess
import time
import sys
import os

def start_services():
    print("Starting NIDS Dashboard and Background Monitor...")

    if os.path.exists("live_predictions.csv"):
        print("Clearing old live_predictions.csv...")
        try:
            os.remove("live_predictions.csv")
        except Exception:
            pass

    if os.path.exists(".stop_capture"):
        try:
            os.remove(".stop_capture")
        except Exception:
            pass

    monitor_process = subprocess.Popen([sys.executable, "network_monitor.py"], stdout=sys.stdout, stderr=sys.stderr)
    print(f"Network monitor started (PID: {monitor_process.pid})")

    dashboard_process = subprocess.Popen(["streamlit", "run", "dashboard.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Streamlit dashboard started (PID: {dashboard_process.pid})")
    print("\nSetup complete! Go to http://localhost:8501 in your browser to view the dashboard.\n")

    try:
        while True:
            time.sleep(1)
            if monitor_process.poll() is not None:
                print(f"Error: Network monitor crashed with code {monitor_process.returncode}")
                break
            if dashboard_process.poll() is not None:
                print(f"Error: Dashboard crashed with code {dashboard_process.returncode}")
                break
    except KeyboardInterrupt:
        print("\nStopping all services gracefully...")
    finally:
        with open(".stop_capture", "w") as f:
            f.write("stop")

        time.sleep(1)

        if monitor_process.poll() is None:
            monitor_process.terminate()
        if dashboard_process.poll() is None:
            dashboard_process.terminate()

        print("Services stopped.")

if __name__ == "__main__":
    start_services()
