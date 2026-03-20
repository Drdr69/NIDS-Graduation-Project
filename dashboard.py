import sys
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import time
import subprocess

st.set_page_config(page_title="NIDS Command Center", page_icon="🛡️", layout="wide")

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
                if 'Flow ID' in df.columns:
                    df = df.drop_duplicates(subset=['Flow ID'], keep='last')
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])
                return df
        except Exception:
            pass
    return pd.DataFrame()

df = load_data()

# --- Sidebar UI Controls ---
st.sidebar.title("🛡️ NIDS Controls")

if 'capturing' not in st.session_state:
    try:
        pid_check = subprocess.run(["pgrep", "-f", "live_capture.py"], capture_output=True, text=True)
        st.session_state.capturing = bool(pid_check.stdout.strip())
    except:
        st.session_state.capturing = False

if st.sidebar.button("▶️ Start Live Extract", use_container_width=True):
    if not st.session_state.capturing:
        if os.path.exists(STOP_FILE):
            os.remove(STOP_FILE)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(PCAP_DIR, f"capture_{timestamp}.pcap")

        subprocess.Popen([sys.executable, "live_capture.py", pcap_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        st.session_state.capturing = True
        st.session_state.current_pcap = pcap_file
        time.sleep(1)
        st.rerun()

if st.sidebar.button("⏸️ Pause & Analyze", use_container_width=True):
    if st.session_state.capturing:
        with open(STOP_FILE, "w") as f:
            f.write("stop")

        with st.spinner("Stopping capture and securely analyzing PCAP..."):
            time.sleep(3)
            st.session_state.capturing = False

            pcap_file = st.session_state.get('current_pcap')
            if pcap_file and os.path.exists(pcap_file):
                subprocess.run([sys.executable, "process_pcap.py", pcap_file, PREDICTIONS_FILE])
                st.sidebar.success("Offline Analysis complete!")
            else:
                st.sidebar.error("PCAP file not found or empty.")
            time.sleep(1)
            st.rerun()

if st.session_state.capturing:
    st.sidebar.success("🟢 Live Capture: **RUNNING**")
else:
    st.sidebar.info("⚫ Live Capture: **PAUSED**")

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Filter Settings")
show_only_attacks = st.sidebar.checkbox("🚨 Show Only Threats", value=False)
min_prob = st.sidebar.slider("Minimum Confidence (%)", 0, 100, 50)

if st.sidebar.button("🗑️ Clear All Network Data", use_container_width=True):
    if os.path.exists(PREDICTIONS_FILE):
        pd.DataFrame(columns=['Flow ID', 'Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Total Packets', 'Total Bytes', 'Flow Duration (s)', 'Packets/s', 'Bytes/s', 'Prediction', 'Probability']).to_csv(PREDICTIONS_FILE, index=False)
    st.rerun()

# --- Main Dashboard Header ---
st.title("Network Intrusion Detection Command Center")
st.markdown("Real-time monitoring, advanced threat intelligence, and ML-based flow classification.")

if df.empty:
    st.warning("No network data found. Ensure the backend monitor is running (`sudo python main.py`) or click **'Start Live Extract'** in the sidebar.")
else:
    # Filter based on user settings
    df = df[df['Probability'] >= (min_prob / 100.0)]
    if show_only_attacks:
        df = df[df['Prediction'] != 'BENIGN']

    if df.empty:
        st.info("No data matches the current strict filter settings.")
    else:
        # Pre-calculate essential metrics
        total_flows = len(df)
        if 'Total Packets' not in df.columns:
            df['Total Packets'] = 1
        if 'Total Bytes' not in df.columns:
            df['Total Bytes'] = 0

        total_packets_count = df['Total Packets'].sum()
        total_mbytes = df['Total Bytes'].sum() / (1024 * 1024)

        attacks_df = df[df['Prediction'] != 'BENIGN']
        total_attacks = len(attacks_df)

        # Calculate recent threat severity (gauge metric)
        # Ratio of attacks to total traffic in the last 100 flows
        recent_flows = df.tail(100)
        recent_attacks = len(recent_flows[recent_flows['Prediction'] != 'BENIGN'])
        threat_score = (recent_attacks / len(recent_flows)) * 100 if not recent_flows.empty else 0

        # --- 1. High-Level Metrics Row ---
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Flows", f"{total_flows:,}")
        col2.metric("Total Packets", f"{total_packets_count:,}")
        col3.metric("Data Processed (MB)", f"{total_mbytes:.2f}")
        col4.metric("Threats Blocked", f"{total_attacks:,}", delta_color="inverse")

        latest_attack = attacks_df.iloc[-1]['Prediction'] if total_attacks > 0 else "Safe"
        col5.metric("Last Threat Type", latest_attack, delta="Critical" if latest_attack != "Safe" else "Normal", delta_color="inverse" if latest_attack != "Safe" else "normal")

        st.markdown("---")

        # --- Tabs ---
        tab1, tab2, tab3, tab4 = st.tabs([
            "🚨 Threat Intelligence",
            "📈 Network Analytics",
            "🕵️ Detailed Flow Logs",
            "💾 Export Reports"
        ])

        # --- TAB 1: Threat Intelligence ---
        with tab1:
            col_gauge, col_top = st.columns([1, 2])

            with col_gauge:
                st.subheader("Current Threat Score")
                st.caption("Based on frequency of attacks in the latest 100 flows.")
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=threat_score,
                    title={'text': "Danger Level (%)"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "darkred" if threat_score > 50 else "orange" if threat_score > 20 else "green"},
                        'steps': [
                            {'range': [0, 20], 'color': "lightgreen"},
                            {'range': [20, 50], 'color': "yellow"},
                            {'range': [50, 100], 'color': "salmon"}
                        ]
                    }
                ))
                st.plotly_chart(fig_gauge, use_container_width=True)

            with col_top:
                st.subheader("Top Attackers & Targets")
                st.caption("Identify compromised nodes and external threats rapidly.")
                if total_attacks > 0:
                    c_att, c_tar = st.columns(2)
                    with c_att:
                        top_attackers = attacks_df['Source IP'].value_counts().head(5).reset_index()
                        top_attackers.columns = ['IP Address', 'Attacks Launched']
                        fig_att = px.bar(top_attackers, x='Attacks Launched', y='IP Address', orientation='h',
                                         title="Top 5 Malicious Source IPs", color_discrete_sequence=['#d62728'])
                        fig_att.update_layout(yaxis={'categoryorder':'total ascending'}, margin=dict(l=0, r=0, t=30, b=0))
                        st.plotly_chart(fig_att, use_container_width=True)

                    with c_tar:
                        top_targets = attacks_df['Dest IP'].value_counts().head(5).reset_index()
                        top_targets.columns = ['IP Address', 'Times Targeted']
                        fig_tar = px.bar(top_targets, x='Times Targeted', y='IP Address', orientation='h',
                                         title="Top 5 Attacked Destinations", color_discrete_sequence=['#ff7f0e'])
                        fig_tar.update_layout(yaxis={'categoryorder':'total ascending'}, margin=dict(l=0, r=0, t=30, b=0))
                        st.plotly_chart(fig_tar, use_container_width=True)
                else:
                    st.success("No attacks recorded yet. Top IP charts will appear here when threats are detected.")

        # --- TAB 2: Network Analytics ---
        with tab2:
            st.subheader("Network Danger Level (Volume Over Time)")
            st.caption("Observe spikes in network activity during downloads, video streaming, or DDoS volumetric attacks.")

            df['Time Window'] = df['Timestamp'].dt.floor('2S')
            df['Threat Category'] = df['Prediction'].apply(lambda x: 'Benign' if x == 'BENIGN' else 'Attack')

            time_agg = df.groupby(['Time Window', 'Threat Category'])['Total Packets'].sum().reset_index()

            if not time_agg.empty:
                fig_area = px.area(time_agg, x='Time Window', y='Total Packets', color='Threat Category',
                                   color_discrete_map={'Benign': '#2ca02c', 'Attack': '#d62728'},
                                   labels={'Time Window': 'Local Time', 'Total Packets': 'Packets / 2s'})
                fig_area.update_layout(hovermode="x unified", margin=dict(t=10))
                st.plotly_chart(fig_area, use_container_width=True)

            c_pie, c_proto = st.columns(2)
            with c_pie:
                st.subheader("Threat Classification Breakdown")
                class_counts = df['Prediction'].value_counts().reset_index()
                class_counts.columns = ['Classification', 'Count']
                fig_pie = px.pie(class_counts, names='Classification', values='Count', hole=0.4,
                                 color_discrete_sequence=px.colors.qualitative.Set3)
                fig_pie.update_traces(textinfo='percent+label')
                fig_pie.update_layout(margin=dict(t=10, b=10))
                st.plotly_chart(fig_pie, use_container_width=True)

            with c_proto:
                st.subheader("Protocol Distribution (TCP vs UDP)")
                st.caption("Useful for identifying UDP floods vs TCP SYN floods.")
                proto_counts = df['Protocol'].value_counts().reset_index()
                proto_counts.columns = ['Protocol', 'Flows']
                fig_proto = px.bar(proto_counts, x='Protocol', y='Flows', color='Protocol',
                                   color_discrete_sequence=px.colors.qualitative.Pastel)
                fig_proto.update_layout(margin=dict(t=10, b=10))
                st.plotly_chart(fig_proto, use_container_width=True)

        # --- TAB 3: Detailed Flow Logs ---
        with tab3:
            st.subheader("Raw Network Flow Intelligence")
            st.caption("Deep inspection of the most recent active network connections. Sorted by newest first.")

            display_cols = ['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Total Packets', 'Total Bytes', 'Flow Duration (s)', 'Packets/s', 'Bytes/s', 'Prediction', 'Probability']
            available_cols = [col for col in display_cols if col in df.columns]

            # Show the last 1000 flows for performance, newest first
            st.dataframe(df.tail(1000)[::-1][available_cols], use_container_width=True, height=500)

        # --- TAB 4: Export Reports ---
        with tab4:
            st.subheader("Download Security Reports")
            st.markdown("Extract forensic logs for offline SIEM analysis or compliance reporting.")

            if total_attacks > 0:
                csv_attacks = attacks_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download Threat Log (Attacks Only)",
                    data=csv_attacks,
                    file_name=f"NIDS_Threat_Report_{time.strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    type="primary"
                )

            csv_all = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Full Network Log",
                data=csv_all,
                file_name=f"NIDS_Full_Traffic_{time.strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )

if "st_autorefresh" not in sys.modules:
    time.sleep(2)
    st.rerun()
