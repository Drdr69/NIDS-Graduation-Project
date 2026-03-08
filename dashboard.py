import sys
import streamlit as st
import pandas as pd
import plotly.express as px
import os
import time
import subprocess

st.set_page_config(page_title="NIDS Real-Time Dashboard", layout="wide")

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PREDICTIONS_FILE = os.path.join(BASE_DIR, 'live_predictions.csv')
PCAP_DIR = os.path.join(BASE_DIR, 'captured_pcaps')
STOP_FILE = os.path.join(BASE_DIR, '.stop_capture')

if not os.path.exists(PCAP_DIR):
    os.makedirs(PCAP_DIR)

st.title("🛡️ Network Intrusion Detection System")
st.markdown("Monitoring live network traffic using Machine Learning (Trained on CICIDS2017)")

# Use st_autorefresh for idiomatic Streamlit auto-refreshing instead of blocking while True loop
try:
    from streamlit_autorefresh import st_autorefresh
    # Refresh every 2 seconds
    st_autorefresh(interval=2000, limit=None, key="data_refresh")
except ImportError:
    pass

def load_data():
    if os.path.exists(PREDICTIONS_FILE):
        try:
            df = pd.read_csv(PREDICTIONS_FILE)
            if not df.empty:
                # Deduplicate based on Flow ID to prevent dashboard metric inflation from live active flow updates
                if 'Flow ID' in df.columns:
                    df = df.drop_duplicates(subset=['Flow ID'], keep='last')
                return df
        except Exception:
            pass
    return pd.DataFrame()

df = load_data()

# --- Sidebar Controls ---
st.sidebar.header("Capture Controls")

if 'capturing' not in st.session_state:
    # Check if a live_capture process is currently running
    try:
        pid_check = subprocess.run(["pgrep", "-f", "live_capture.py"], capture_output=True, text=True)
        st.session_state.capturing = bool(pid_check.stdout.strip())
    except:
        st.session_state.capturing = False

if st.sidebar.button("▶️ Start Extracting"):
    if not st.session_state.capturing:
        if os.path.exists(STOP_FILE):
            os.remove(STOP_FILE)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(PCAP_DIR, f"capture_{timestamp}.pcap")

        # Start capture in background
        subprocess.Popen([sys.executable, "live_capture.py", pcap_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        st.session_state.capturing = True
        st.session_state.current_pcap = pcap_file
        st.sidebar.success("Capture started!")
        time.sleep(1)
        st.rerun()

if st.sidebar.button("⏸️ Pause & Analyze"):
    if st.session_state.capturing:
        with open(STOP_FILE, "w") as f:
            f.write("stop")

        with st.spinner("Stopping capture and analyzing PCAP..."):
            time.sleep(3) # Give it time to flush and save the PCAP
            st.session_state.capturing = False

            pcap_file = st.session_state.get('current_pcap')
            if pcap_file and os.path.exists(pcap_file):
                # Analyze it
                subprocess.run([sys.executable, "process_pcap.py", pcap_file, PREDICTIONS_FILE])
                st.sidebar.success("Analysis complete!")
            else:
                st.sidebar.error("PCAP file not found or empty.")
            time.sleep(1)
            st.rerun()

if st.session_state.capturing:
    st.sidebar.info("🔴 Live Capture is RUNNING")
else:
    st.sidebar.info("⚫ Capture is PAUSED")

st.sidebar.markdown("---")
if st.sidebar.button("🗑️ Clear Dashboard Data"):
    if os.path.exists(PREDICTIONS_FILE):
        os.remove(PREDICTIONS_FILE)
    st.rerun()

# --- Main Dashboard ---
if df.empty:
    st.warning("No data found. Click 'Start Extracting' in the sidebar or run `python network_monitor.py`.")
else:
    # 1. Top Metrics
    total_flows = len(df)

    # Calculate attacks (anything not BENIGN)
    attacks_df = df[df['Prediction'] != 'BENIGN']
    total_attacks = len(attacks_df)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Flows Analyzed", total_flows)
    col2.metric("Total Attacks Detected", total_attacks, delta_color="inverse")

    latest_attack = attacks_df.iloc[-1]['Prediction'] if total_attacks > 0 else "None"
    col3.metric("Latest Threat", latest_attack)

    st.markdown("---")

    # 2. Charts Row
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Traffic Distribution")
        class_counts = df['Prediction'].value_counts().reset_index()
        class_counts.columns = ['Prediction', 'Count']
        fig_pie = px.pie(class_counts, names='Prediction', values='Count', hole=0.4,
                         color_discrete_sequence=px.colors.qualitative.Pastel)
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        st.subheader("Recent Alerts (Attacks)")
        if total_attacks > 0:
            # Show last 10 attacks
            recent_attacks = attacks_df.tail(10)[::-1]
            st.dataframe(recent_attacks[['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Prediction', 'Probability']],
                         use_container_width=True)
        else:
            st.success("No attacks detected recently! System is secure.")

    # 3. Full Data View
    st.subheader("Live Traffic Feed")
    st.dataframe(df.tail(20)[::-1], use_container_width=True)

# Manual fallback for refresh
if "st_autorefresh" not in sys.modules:
    time.sleep(2)
    st.rerun()
