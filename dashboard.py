import sys
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import time

st.set_page_config(page_title="NIDS Command Center", page_icon="🛡️", layout="wide")

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PREDICTIONS_FILE = os.path.join(BASE_DIR, 'live_predictions.csv')
PAUSE_FILE = os.path.join(BASE_DIR, '.pause_monitor')

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
st.sidebar.markdown("Control the flow of packets into the dashboard and filter the displayed noise.")

if os.path.exists(PAUSE_FILE):
    is_paused = True
    st.sidebar.info("⚫ Live Detection: **PAUSED**")
else:
    is_paused = False
    st.sidebar.success("🟢 Live Detection: **RUNNING**")

if st.sidebar.button("▶️ Resume Live Detection" if is_paused else "⏸️ Pause Detection", use_container_width=True):
    if is_paused:
        os.remove(PAUSE_FILE)
        st.sidebar.success("Resuming packet flow...")
    else:
        with open(PAUSE_FILE, "w") as f:
            f.write("pause")
        st.sidebar.warning("Pausing new packet flow...")
    time.sleep(1)
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Filter Settings")
show_only_attacks = st.sidebar.checkbox("🚨 Show Only Threats", value=False)
min_prob = st.sidebar.slider("Minimum Confidence (%)", 0, 100, 50)

if st.sidebar.button("🗑️ Clear All Network Data", use_container_width=True):
    header = ['Flow ID', 'Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Total Packets', 'Total Bytes', 'Flow Duration (s)', 'Packets/s', 'Bytes/s', 'Prediction', 'Probability', 'Detection Engine', 'XAI Explanation', 'Mitigation Status']
    pd.DataFrame(columns=header).to_csv(PREDICTIONS_FILE, index=False)
    st.rerun()

# --- Main Dashboard Header ---
st.title("Network Intrusion Detection Command Center")
st.markdown("Real-time monitoring, active mitigation (NIPS), and Explainable AI flow classification.")

if df.empty:
    st.warning("No network data found. Ensure the backend monitor is running (`sudo python main.py`) and Live Detection is not paused.")
else:
    # Filter
    df = df[df['Probability'] >= (min_prob / 100.0)]
    if show_only_attacks:
        df = df[df['Prediction'] != 'BENIGN']

    if df.empty:
        st.info("No data matches the current strict filter settings.")
    else:
        total_flows = len(df)
        total_packets_count = df['Total Packets'].sum() if 'Total Packets' in df.columns else 1
        total_mbytes = df['Total Bytes'].sum() / (1024 * 1024) if 'Total Bytes' in df.columns else 0

        attacks_df = df[df['Prediction'] != 'BENIGN']
        total_attacks = len(attacks_df)

        recent_flows = df.tail(100)
        recent_attacks = len(recent_flows[recent_flows['Prediction'] != 'BENIGN'])
        threat_score = (recent_attacks / len(recent_flows)) * 100 if not recent_flows.empty else 0

        # --- High-Level Metrics Row ---
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Flows", f"{total_flows:,}")
        col2.metric("Total Packets", f"{total_packets_count:,}")
        col3.metric("Data Processed (MB)", f"{total_mbytes:.2f}")
        col4.metric("Threats Blocked", f"{total_attacks:,}", delta_color="inverse")

        latest_attack = attacks_df.iloc[-1]['Prediction'] if total_attacks > 0 else "Safe"
        col5.metric("Last Threat Type", latest_attack, delta="Critical" if latest_attack != "Safe" else "Normal", delta_color="inverse" if latest_attack != "Safe" else "normal")

        st.markdown("---")

        # --- Tabs ---
        tab1, tab2, tab3 = st.tabs([
            "🚨 Active Alerts & Mitigations",
            "📈 Network Analytics",
            "🕵️ Detailed Flow Logs"
        ])

        # --- TAB 1: Alerts & Mitigations ---
        with tab1:
            st.info("**What is this page?** This page strictly isolates hostile network traffic (attacks) and explains exactly why the Machine Learning model flagged it using Explainable AI (XAI). It also details the active system mitigation (e.g. firewall blocking) taken against the attacker.")

            if total_attacks > 0:
                # Top Attackers charts
                c_att, c_tar = st.columns(2)
                with c_att:
                    top_attackers = attacks_df['Source IP'].value_counts().head(5).reset_index()
                    top_attackers.columns = ['Attacker IP Address', 'Attacks Launched']
                    fig_att = px.bar(top_attackers, x='Attacks Launched', y='Attacker IP Address', orientation='h',
                                     title="Top 5 Malicious Source IPs", color_discrete_sequence=['#d62728'])
                    fig_att.update_layout(yaxis={'categoryorder':'total ascending'}, margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_att, use_container_width=True)

                with c_tar:
                    top_targets = attacks_df['Dest IP'].value_counts().head(5).reset_index()
                    top_targets.columns = ['Target IP Address', 'Times Targeted']
                    fig_tar = px.bar(top_targets, x='Times Targeted', y='Target IP Address', orientation='h',
                                     title="Top 5 Attacked Destinations", color_discrete_sequence=['#ff7f0e'])
                    fig_tar.update_layout(yaxis={'categoryorder':'total ascending'}, margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_tar, use_container_width=True)

                st.subheader("Hostile Flow Log")
                display_cols = ['Timestamp', 'Source IP', 'Dest IP', 'Total Packets', 'Prediction', 'Probability', 'Detection Engine', 'XAI Explanation', 'Mitigation Status']
                avail = [c for c in display_cols if c in attacks_df.columns]
                st.dataframe(attacks_df.tail(100)[::-1][avail], use_container_width=True)
            else:
                st.success("No attacks recorded yet. System is secure.")

        # --- TAB 2: Network Analytics ---
        with tab2:
            st.info("**What is this page?** This section graphs overall traffic patterns. You will see spikes in the 'Total Packets' Area Chart when you download a large file, watch a video, or experience a volumetric DDoS attack. The gauge displays your immediate danger level based on the last 100 network flows.")

            col_gauge, col_area = st.columns([1, 2])

            with col_gauge:
                st.subheader("Current Threat Score")
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

            with col_area:
                st.subheader("Network Danger Level (Volume Over Time)")
                df['Time Window'] = df['Timestamp'].dt.floor('2S')
                df['Threat Category'] = df['Prediction'].apply(lambda x: 'Benign' if x == 'BENIGN' else 'Attack')

                time_agg = df.groupby(['Time Window', 'Threat Category'])['Total Packets'].sum().reset_index()

                if not time_agg.empty:
                    fig_area = px.area(time_agg, x='Time Window', y='Total Packets', color='Threat Category',
                                       color_discrete_map={'Benign': '#2ca02c', 'Attack': '#d62728'},
                                       labels={'Time Window': 'Local Time', 'Total Packets': 'Packets / 2s'})
                    fig_area.update_layout(hovermode="x unified", margin=dict(t=10))
                    st.plotly_chart(fig_area, use_container_width=True)

        # --- TAB 3: Detailed Flow Logs ---
        with tab3:
            st.info("**What is this page?** This is the raw network ledger. It displays every active flow regardless of threat status. Data with the same Source IP and Destination Port is grouped into a single bidirectional 'Flow'.")
            st.subheader("All Network Activity")

            display_cols = ['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Total Packets', 'Total Bytes', 'Flow Duration (s)', 'Packets/s', 'Bytes/s', 'Prediction', 'Probability']
            available_cols = [col for col in display_cols if col in df.columns]

            st.dataframe(df.tail(1000)[::-1][available_cols], use_container_width=True, height=600)

            # Export controls
            st.markdown("---")
            st.subheader("Download Security Reports")
            c_rep1, c_rep2 = st.columns(2)
            with c_rep1:
                if total_attacks > 0:
                    st.download_button(
                        label="📥 Download Threat Log (Attacks Only)",
                        data=attacks_df.to_csv(index=False).encode('utf-8'),
                        file_name=f"NIDS_Threats_{time.strftime('%Y%m%d')}.csv",
                        mime="text/csv", type="primary"
                    )
            with c_rep2:
                st.download_button(
                    label="📥 Download Full Network Log",
                    data=df.to_csv(index=False).encode('utf-8'),
                    file_name=f"NIDS_Traffic_{time.strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )

if "st_autorefresh" not in sys.modules:
    time.sleep(2)
    st.rerun()
