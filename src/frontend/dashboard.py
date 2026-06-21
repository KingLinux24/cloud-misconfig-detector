import json
from pathlib import Path
import streamlit as st

# Set page layout and configuration
st.set_page_config(
    page_title="Cloud Misconfiguration Scanner Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Application Title
st.title("🛡️ Cloud Misconfiguration Scanner Dashboard")
st.markdown("Real-time security auditing and compliance insights for your Terraform configurations.")
st.divider()

# Load Report Data
report_path = Path("data/processed/report.json")

if not report_path.exists():
    st.error(f"❌ Report file not found at `{report_path}`. Please run `python -m src.utils.run` first to generate scan data.")
else:
    with open(report_path, "r") as f:
        report_data = json.load(f)

    # 1. Top Level Metrics Layout
    res_count = report_data.get("resource_count", 0)
    find_count = report_data.get("finding_count", 0)
    findings = report_data.get("findings", [])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Total Scanned Resources", value=res_count)
    with col2:
        # Use color indicator for findings
        st.metric(
            label="Identified Misconfigurations", 
            value=find_count, 
            delta=f"{find_count} Alert(s)" if find_count > 0 else "Clean",
            delta_color="inverse" if find_count > 0 else "normal"
        )
    with col3:
        # Calculate an overall security posture grade
        if find_count == 0:
            grade, color = "A+ (Excellent)", "green"
        elif any(f.get("severity") == "critical" for f in findings):
            grade, color = "F (Action Required)", "red"
        elif find_count > 2:
            grade, color = "C (Warning)", "orange"
        else:
            grade, color = "B (Good)", "blue"
        st.markdown(f"### Security Posture\n### :{color}[{grade}]")

    st.divider()

    # 2. Main Content Display
    if find_count == 0:
        st.success("🎉 Great job! No security misconfigurations were detected in the analyzed Terraform assets.")
    else:
        st.subheader("🚨 Detected Vulnerabilities")
        
        # Display each finding cleanly inside an expander tab
        for idx, item in enumerate(findings):
            # Define severity colors
            sev = item.get("severity", "info").lower()
            sev_colors = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM", "low": "🔵 LOW", "info": "⚪ INFO"}
            sev_badge = sev_colors.get(sev, sev.upper())

            # Expander header title string
            expander_title = f"{sev_badge} | {item.get('title')} ({item.get('id')})"
            
            with st.expander(expander_title, expanded=(idx == 0)):
                c1, c2 = st.columns([2, 1])
                
                with c1:
                    st.markdown(f"**Category:** `{item.get('category')}`")
                    st.markdown(f"**Remediation Action:** {item.get('remediation')}")
                    
                    # File tracking info
                    resource_info = item.get("resource", {})
                    st.caption(f"📍 Detected in file: `{resource_info.get('file', 'Unknown')}`")
                
                with c2:
                    st.markdown(f"**Risk Score Metrics:**")
                    st.progress(item.get("risk_score", 0) / 100)
                    st.caption(f"Calculated Score: **{item.get('risk_score', 0)} / 100**")

                # Show code context / metadata gathered as evidence
                st.markdown("**Evidence Payload Data:**")
                st.json(item.get("evidence", {}))
