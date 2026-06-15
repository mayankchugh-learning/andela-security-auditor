import streamlit as st
import requests

API_BASE = "http://localhost:8000"

st.set_page_config(page_title="Security Guardrail Auditor", page_icon="🛡️", layout="wide")
st.title("🛡️ Enterprise Security Guardrail Auditor")
st.caption("Scan Terraform and CloudFormation configs for security misconfigurations")

# --- Sidebar: upload ---
st.sidebar.header("Upload Config File")
uploaded = st.sidebar.file_uploader("Choose a .tf or .yaml file", type=["tf", "yaml", "yml"])

if uploaded and st.sidebar.button("Run Scan"):
    with st.spinner("Scanning..."):
        resp = requests.post(
            f"{API_BASE}/scan",
            files={"file": (uploaded.name, uploaded.getvalue(), "text/plain")},
        )
    if resp.ok:
        data = resp.json()
        st.success(f"Scan complete — Risk Level: **{data['risk_level']}**")
        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", data["risk_score"])
        col2.metric("Findings", data["total_findings"])
        col3.metric("Risk Level", data["risk_level"])

        if data["findings"]:
            st.subheader("Findings")
            import pandas as pd
            df = pd.DataFrame(data["findings"])
            # Colour-code severity
            def colour_severity(val):
                colours = {"Critical": "background-color: #ff4444", "High": "background-color: #ff8800",
                           "Medium": "background-color: #ffcc00", "Low": "background-color: #88cc00"}
                return colours.get(val, "")
            st.dataframe(df.style.applymap(colour_severity, subset=["severity"]), use_container_width=True)
        else:
            st.balloons()
            st.info("No security issues found. Infrastructure is clean!")
    else:
        st.error(f"Scan failed: {resp.text}")

# --- Scan History ---
st.divider()
st.subheader("Scan History")

try:
    scans = requests.get(f"{API_BASE}/scans").json()
    if scans:
        import pandas as pd
        df = pd.DataFrame(scans)
        df = df.rename(columns={
            "scan_id": "ID", "filename": "File", "file_type": "Type",
            "risk_score": "Score", "risk_level": "Risk Level",
            "total_findings": "Findings", "scanned_at": "Scanned At"
        })
        st.dataframe(df, use_container_width=True)

        selected_id = st.selectbox("View scan details", [s["scan_id"] for s in scans])
        if st.button("Load Details"):
            detail = requests.get(f"{API_BASE}/scans/{selected_id}").json()
            st.json(detail)
    else:
        st.info("No scans yet. Upload a config file to get started.")
except Exception:
    st.warning("Could not connect to API. Make sure the FastAPI server is running on port 8000.")
