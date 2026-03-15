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

# Auto-refresh
try:
    from streamlit_autorefresh import st_autorefresh
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
                # Ensure Timestamp is datetime for time-series plotting
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])
                return df
        except Exception:
            pass
    return pd.DataFrame()

df = load_data()

# --- Sidebar UI Controls ---
st.sidebar.header("🛡️ Capture Controls")

# Determine active capture state securely
if 'capturing' not in st.session_state:
    try:
        # Check running processes
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

        # Start capture in the background
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

        with st.spinner("Stopping capture and analyzing PCAP securely..."):
            time.sleep(3)
            st.session_state.capturing = False

            pcap_file = st.session_state.get('current_pcap')
            if pcap_file and os.path.exists(pcap_file):
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
st.sidebar.header("⚙️ View Settings")
show_only_attacks = st.sidebar.checkbox("Show Only Attacks", value=False)
min_prob = st.sidebar.slider("Minimum Prediction Confidence (%)", 0, 100, 50)

if st.sidebar.button("🗑️ Clear Dashboard Data"):
    if os.path.exists(PREDICTIONS_FILE):
        os.remove(PREDICTIONS_FILE)
    st.rerun()

# --- Main Dashboard Header ---
st.title("Network Intrusion Detection System")
st.markdown("Real-time monitoring and ML-based flow classification.")

# --- Content Area ---
if df.empty:
    st.warning("No network data found. Click **'Start Extracting'** in the sidebar or run `python network_monitor.py`.")
else:
    # Filter based on user settings
    df = df[df['Probability'] >= (min_prob / 100.0)]
    if show_only_attacks:
        df = df[df['Prediction'] != 'BENIGN']

    if df.empty:
        st.info("No data matches current filter settings.")
    else:
        # Calculate key metrics
        total_flows = len(df)
        if 'Total Packets' not in df.columns:
            df['Total Packets'] = 1 # Backwards compatibility

        total_packets_count = df['Total Packets'].sum()
        attacks_df = df[df['Prediction'] != 'BENIGN']
        total_attacks = len(attacks_df)

        # 1. Metric Row
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Flows Analyzed", total_flows)
        col2.metric("Total Packets Evaluated", total_packets_count)
        col3.metric("Total Threats Detected", total_attacks, delta_color="inverse")
        latest_attack = attacks_df.iloc[-1]['Prediction'] if total_attacks > 0 else "None"
        col4.metric("Latest Threat Class", latest_attack)

        st.markdown("---")

        # Tabs for better organization
        tab1, tab2, tab3 = st.tabs(["📊 Live Activity", "📈 Flow Analytics", "🔍 Detailed Insights"])

        with tab1:
            st.subheader("Network Danger Level (Packets Over Time)")
            st.markdown("Observe spikes in network activity during downloads, video streaming, or DDoS attacks.")

            # Floor by 2-seconds to aggregate packet counts securely
            df['Time Window'] = df['Timestamp'].dt.floor('2S')
            df['Threat Category'] = df['Prediction'].apply(lambda x: 'Benign' if x == 'BENIGN' else 'Attack')

            time_agg = df.groupby(['Time Window', 'Threat Category'])['Total Packets'].sum().reset_index()

            if not time_agg.empty:
                fig_area = px.area(time_agg, x='Time Window', y='Total Packets', color='Threat Category',
                                   color_discrete_map={'Benign': '#2ca02c', 'Attack': '#d62728'},
                                   labels={'Time Window': 'Time', 'Total Packets': 'Packet Volume'},
                                   title="Live Packet Volume categorized by Threat Level")
                fig_area.update_layout(xaxis_title=None, hovermode="x unified")
                st.plotly_chart(fig_area, use_container_width=True)
            else:
                st.info("Waiting for enough time-series data...")

        with tab2:
            st.subheader("Threat Classification Distribution")
            class_counts = df['Prediction'].value_counts().reset_index()
            class_counts.columns = ['Classification', 'Count']
            fig_pie = px.pie(class_counts, names='Classification', values='Count', hole=0.4,
                             color_discrete_sequence=px.colors.qualitative.Set3)
            fig_pie.update_traces(textinfo='percent+label')
            st.plotly_chart(fig_pie, use_container_width=True)

        with tab3:
            st.subheader("Detailed Flow Insights")
            st.markdown("In-depth technical breakdown of recent active network connections.")

            # Display detailed metrics added previously (if they exist)
            display_cols = ['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Total Packets', 'Total Bytes', 'Flow Duration (s)', 'Packets/s', 'Prediction', 'Probability']
            available_cols = [col for col in display_cols if col in df.columns]

            st.dataframe(df.tail(30)[::-1][available_cols], use_container_width=True)

if "st_autorefresh" not in sys.modules:
    time.sleep(2)
    st.rerun()
