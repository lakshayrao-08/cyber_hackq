import streamlit as st
import time
from siem_defender import siem_system

# Page Layout configuration
st.set_page_config(page_title=" SIEM Dashboard", layout="wide", page_icon="🛡️")

st.title("🛡️ SecureOps Autonomous SIEM Analytics Console")
st.subheader("Real-Time Infrastructure Telemetry & Behavioral Threat Correlation")
st.markdown("---")
# Sidebar Configuration Layout
st.sidebar.header("Host Infrastructure Metrics")
status_placeholder = st.sidebar.empty()
cpu_gauge = st.sidebar.progress(0)
ram_gauge = st.sidebar.progress(0)

# Main Screen Dashboard Structure layouts
col1, col2 = st.columns([1, 2])

with col1:
    st.markdown("### 📋 Node Operational Blueprint")
    identity_card = st.empty()
    metric_summary = st.empty()

with col2:
    st.markdown("### 🚨 Threat Isolation Alert Stream")
    alerts_placeholder = st.empty()

# Real-time state replication cycle execution loop
while True:
    state = siem_system.generate_live_dashboard_data()
    
    # Update sidebar components
    status_placeholder.success(f"Engine Status: {state['engine_status']}")
    cpu_gauge.progress(int(state['global_metrics']['cpu_utilization']))
    ram_gauge.progress(int(state['global_metrics']['memory_utilization']))
    
    # Update left card
    identity_card.info(f"**Target Monitored Machine Name:**\n{state['node_identity']}")
    metric_summary.metric(
        label="Total Suspicious System Indicators Intercepted", 
        value=state['total_alerts_captured']
    )
    
    # Render active security metrics alerts table stream
    if len(state['active_alerts']) == 0:
        alerts_placeholder.info("System fully secure. Network interfaces reporting clean status packets.")
    else:
        # Rebuild formatted markdown structures for security output logs
        md_log = ""
        for alert in state['active_alerts']:
            color = "red" if alert['severity'] == "CRITICAL" or alert['severity'] == "HIGH" else "orange"
            md_log += f"""
            ### :{color}[[{alert['severity']}] - {alert['subsystem']}]
            * **Timestamp:** `{alert['timestamp']}` | **Process Target:** `{alert['entity_name']} (PID: {alert['entity_id']})`
            * **Calculated Risk Index Score:** `{alert['risk_score']}/100` | **Action Resolution:** `{alert['mitigation_state']}`
            * **Context:** {alert['details']}
            ---
            """
        alerts_placeholder.markdown(md_log)
        
    time.sleep(2) # Refresh frequency limit configuration