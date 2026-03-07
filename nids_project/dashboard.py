import streamlit as st
import pandas as pd
import plotly.express as px
import time
import os
import subprocess

st.set_page_config(page_title="NIDS Dashboard", layout="wide")

st.title("🛡️ Real-time Network Intrusion Detection System")
st.markdown("This dashboard monitors live network traffic (simulated for unprivileged environments) and predicts malicious activity using Machine Learning (trained on CICIDS2017). You can also upload PCAP files directly for analysis.")

DATA_FILE = "live_predictions.csv"

# Sidebar for file upload
st.sidebar.header("Offline PCAP Analysis")
uploaded_file = st.sidebar.file_uploader("Upload a .pcap file", type=["pcap"])

if uploaded_file is not None:
    # Save the uploaded file temporarily
    temp_pcap = "temp_uploaded.pcap"
    with open(temp_pcap, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.sidebar.success("File uploaded successfully! Processing...")

    # Run the offline processing script
    try:
        result = subprocess.run(["python", "process_pcap.py", temp_pcap, DATA_FILE], capture_output=True, text=True)
        if result.returncode == 0:
            st.sidebar.success("PCAP processed and added to the dashboard!")
        else:
            st.sidebar.error(f"Error processing PCAP: {result.stderr}")
    except Exception as e:
        st.sidebar.error(f"Execution failed: {e}")

    # Clean up temp file
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

    # Load data
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
            # Create a pie chart showing EXACT percentages of each attack type + benign
            pie_data = df['Prediction'].value_counts().reset_index()
            pie_data.columns = ['Attack Type', 'Count']

            fig = px.pie(
                pie_data,
                values='Count',
                names='Attack Type',
                title='Network Threat Types Detected',
                hole=0.4,
                color='Attack Type',
                color_discrete_map={'BENIGN': 'lightgreen'} # Keep benign green, others will be assigned automatically
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)

        with viz_col2:
            st.subheader("Recent Flagged Threats 🚨")
            if not threats_df.empty:
                # Show most recent threats
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

    time.sleep(3) # Update every 3 seconds
