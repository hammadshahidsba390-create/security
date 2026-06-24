import streamlit as st

st.set_page_config(
    page_title="GuardAI — Unified Cyber Defense",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("# 🛡️ GuardAI — Unified Cyber Defense Platform")
st.markdown("*4-layer AI-powered security infrastructure | Developed by Hammad*")
st.divider()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("### 🔍 Layer 1")
    st.markdown("**Code Vulnerability Scanner**")
    st.markdown("CodeBERT · VulGate · 89% accuracy")
    st.markdown("8 languages · OWASP mapped")
    st.success("✅ Active")

with col2:
    st.markdown("### 🌐 Layer 2")
    st.markdown("**Network Intrusion Detection**")
    st.markdown("LSTM · CIC-IDS2018 · 0.9554 ROC-AUC")
    st.markdown("100% attack recall")
    st.success("✅ Active")

with col3:
    st.markdown("### 🦠 Layer 3")
    st.markdown("**Malware Detection**")
    st.markdown("CNN · MalwareBazaar")
    st.warning("🔧 Scheduled: Phase 3")

with col4:
    st.markdown("### 📋 Layer 4")
    st.markdown("**Unified Threat Report**")
    st.markdown("Combined threat intelligence vector")
    st.warning("🔧 Scheduled: Phase 4")

st.divider()
st.markdown("### 👈 Select an active defensive layer from the sidebar menu to begin tracking telemetry.")

st.markdown("#### Execution Matrix Telemetry")
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Languages Supported", "8")
with m2:
    st.metric("CVE Training Samples", "184k")
with m3:
    st.metric("Network ROC-AUC", "0.9554")
with m4:
    st.metric("Attack Recall", "100%")
