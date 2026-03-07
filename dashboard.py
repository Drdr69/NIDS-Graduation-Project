import streamlit as st
import pandas as pd
import plotly.express as px
import time
import os
import subprocess
import signal
from datetime import datetime

st.set_page_config(page_title="NIDS Dashboard", layout="wide")

st.title("🛡️ Real-time Network Intrusion Detection System")
st.markdown("This dashboard predicts malicious activity using Machine Learning (trained on CICIDS2017).")

DATA_FILE = "live_predictions.csv"
CAPTURE_DIR = "captured_pcaps"

if not os.path.exists(CAPTURE_DIR):
    os.makedirs(CAPTURE_DIR)

# Initialize Session State Variables
if 'capturing' not in st.session_state:
    st.session_state.capturing = False
if 'capture_pid' not in st.session_state:
    st.session_state.capture_pid = None
if 'current_pcap' not in st.session_state:
    st.session_state.current_pcap = None

# Sidebar Content
st.sidebar.header("Live Packet Capture")
st.sidebar.markdown("Use this to manually start/stop recording your network traffic into a PCAP file.")

# Status Indicator
if st.session_state.capturing:
    st.sidebar.info("🔴 Status: **CAPTURING LIVE TRAFFIC...**")
else:
    st.sidebar.success("🟢 Status: **IDLE**")

# Start / Stop Buttons
col1, col2 = st.sidebar.columns(2)

with col1:
    if st.button("▶️ Start Extracting", disabled=st.session_state.capturing):
        st.session_state.capturing = True

        # Generate filename based on timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        st.session_state.current_pcap = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")

        # Start the background capture process
        proc = subprocess.Popen(["python", "live_capture.py", st.session_state.current_pcap])
        st.session_state.capture_pid = proc.pid

        st.sidebar.success(f"Started capturing to {st.session_state.current_pcap}")
        st.rerun()

with col2:
    if st.button("⏹️ Pause & Analyze", disabled=not st.session_state.capturing):
        st.session_state.capturing = False

        # Send SIGTERM to smoothly stop the scapy sniffer and save the file
        if st.session_state.capture_pid:
            try:
                os.kill(st.session_state.capture_pid, signal.SIGTERM)
                st.sidebar.success("Capture stopped! Saving PCAP...")
            except ProcessLookupError:
                st.sidebar.error("Capture process already died.")

        # Wait a brief moment for the file to be fully written
        time.sleep(2)

        # If the file exists, analyze it instantly with our ML models
        if st.session_state.current_pcap and os.path.exists(st.session_state.current_pcap):
            st.sidebar.info("Analyzing PCAP data with ML Models...")
            # We call our offline processor to parse the newly saved PCAP
            result = subprocess.run(["python", "process_pcap.py", st.session_state.current_pcap, DATA_FILE], capture_output=True, text=True)

            if result.returncode == 0:
                st.sidebar.success("Analysis Complete! Data added to dashboard.")
            else:
                st.sidebar.warning(f"Error during analysis: {result.stderr}")
        else:
            st.sidebar.error("PCAP file was not found.")

        st.session_state.capture_pid = None
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("Upload PCAP File")
uploaded_file = st.sidebar.file_uploader("Upload a .pcap file", type=["pcap"])

if uploaded_file is not None:
    temp_pcap = "temp_uploaded.pcap"
    with open(temp_pcap, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.sidebar.success("File uploaded successfully! Processing...")
    try:
        result = subprocess.run(["python", "process_pcap.py", temp_pcap, DATA_FILE], capture_output=True, text=True)
        if result.returncode == 0:
            st.sidebar.success("PCAP processed and added to the dashboard!")
        else:
            st.sidebar.error(f"Error processing PCAP: {result.stderr}")
    except Exception as e:
        st.sidebar.error(f"Execution failed: {e}")
    if os.path.exists(temp_pcap):
        os.remove(temp_pcap)

# Main Dashboard Layout
placeholder = st.empty()

while True:
    if not os.path.exists(DATA_FILE):
        with placeholder.container():
            st.warning(f"Waiting for {DATA_FILE} to be generated...")
        time.sleep(2)
        continue

    try:
        df = pd.read_csv(DATA_FILE)
    except Exception as e:
        time.sleep(1)
        continue

    if df.empty:
        with placeholder.container():
            st.warning("No network flows captured yet...")
        time.sleep(2)
        continue

    total_flows = len(df)
    threats_df = df[df['Prediction'] != 'BENIGN']
    total_threats = len(threats_df)
    attack_rate = (total_threats / total_flows) * 100 if total_flows > 0 else 0

    with placeholder.container():
        # Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Flows Analyzed", total_flows)
        col2.metric("Threats Detected", total_threats, f"{attack_rate:.1f}% of traffic", delta_color="inverse")
        col3.metric("Clean Traffic", total_flows - total_threats)

        st.markdown("---")

        # Visualizations
        viz_col1, viz_col2 = st.columns([1, 1])

        with viz_col1:
            st.subheader("Traffic Distribution (Pie Chart)")
            pie_data = df['Prediction'].value_counts().reset_index()
            pie_data.columns = ['Attack Type', 'Count']

            fig = px.pie(
                pie_data,
                values='Count',
                names='Attack Type',
                title='Network Threat Types Detected',
                hole=0.4,
                color='Attack Type',
                color_discrete_map={'BENIGN': 'lightgreen'}
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)

        with viz_col2:
            st.subheader("Recent Flagged Threats 🚨")
            if not threats_df.empty:
                recent_threats = threats_df.tail(10).sort_values(by='Timestamp', ascending=False)
                st.dataframe(
                    recent_threats.style.applymap(lambda x: 'background-color: #ffcccc' if x != 'BENIGN' else '', subset=['Prediction']),
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.success("No threats detected yet!")

        st.subheader("All Live Network Flows")
        st.dataframe(df.tail(20).sort_values(by='Timestamp', ascending=False), use_container_width=True, hide_index=True)

    time.sleep(3)
