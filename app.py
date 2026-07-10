import streamlit as st

st.set_page_config(
    page_title="GuardAI — Unified Cyber Defense",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("# 🛡️ GuardAI — Unified Cyber Defense Platform")
st.markdown("*AI-powered security system — Built by Hammad*")
st.divider()

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown("### 🔍 Layer 1")
    st.markdown("**Code Vulnerability Scanner**")
    st.markdown("UniXcoder · VulGate · 83% accuracy")
    st.markdown("8 languages · OWASP mapped")
    st.success("✅ Active")

with col2:
    st.markdown("### 🌐 Layer 2")
    st.markdown("**Network Intrusion Detection**")
    st.markdown("LSTM · CIC-IDS2018 · 0.9554 ROC-AUC")
    st.markdown("7 attack categories")
    st.success("✅ Active")

with col3:
    st.markdown("### 🦠 Layer 3")
    st.markdown("**Malware Detection**")
    st.markdown("CNN · MalwareBazaar · 77% accuracy")
    st.markdown("10 malware families")
    st.success("✅ Active")

with col4:
    st.markdown("### 🔍 Layer 5")
    st.markdown("**CVE Dependency Scanner**")
    st.markdown("OSV.dev API · Real-time CVEs")
    st.markdown("PyPI · npm · Go · Maven")
    st.success("✅ Active")

with col5:
    st.markdown("### 📋 Layer 4")
    st.markdown("**Unified Threat Report**")
    st.markdown("Combined threat intelligence")
    st.warning("🔧 Coming Soon")

st.divider()
st.markdown("### 👈 Select a layer from the sidebar to begin")

st.markdown("#### Platform Stats")
m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.metric("Languages Supported", "8")
with m2:
    st.metric("CVE Training Samples", "184k")
with m3:
    st.metric("Network ROC-AUC", "0.9554")
with m4:
    st.metric("Malware Families", "10")
with m5:
    st.metric("CVE Databases", "6")

st.divider()
st.caption("GuardAI | Open source defensive security platform | For authorized use only")
