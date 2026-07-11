import streamlit as st

st.set_page_config(
    page_title="GuardAI — Unified Cyber Defense",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("# 🛡️ GuardAI — Unified Cyber Defense Platform")
st.markdown("*AI-powered multi-layer security system — Built by Hammad Shahid*")
st.divider()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("### 🔍 Layer 1")
    st.markdown("**Code Vulnerability Scanner**")
    st.markdown("UniXcoder · VulGate · 83% accuracy · 8 languages")
    st.success("✅ Active")

    st.markdown("### 📦 Layer 5")
    st.markdown("**CVE Dependency Scanner**")
    st.markdown("OSV.dev · Real-time · PyPI/npm/Go/Maven")
    st.success("✅ Active")

with col2:
    st.markdown("### 🌐 Layer 2")
    st.markdown("**Network Intrusion Detection**")
    st.markdown("LSTM · CIC-IDS2018 · 0.9554 ROC-AUC · 7 attacks")
    st.success("✅ Active")

    st.markdown("### 🔑 Layer 6")
    st.markdown("**Secret & API Key Detector**")
    st.markdown("35+ patterns · Entropy analysis · AWS/GitHub/Stripe")
    st.success("✅ Active")

with col3:
    st.markdown("### 🦠 Layer 3")
    st.markdown("**Malware Detection**")
    st.markdown("CNN · MalwareBazaar · 77% accuracy · 10 families")
    st.success("✅ Active")

    st.markdown("### 🤖 Layer 7")
    st.markdown("**Prompt Injection Scanner**")
    st.markdown("20+ attack types · Real-time · AI app protection")
    st.success("✅ Active")

with col4:
    st.markdown("### 🧠 Layer 9")
    st.markdown("**Behavioral Anomaly Engine**")
    st.markdown("Z-score baselines · No signatures · Novel threats")
    st.success("✅ Active")

    st.markdown("### 🛡️ Layer 10")
    st.markdown("**Unified Threat Intelligence**")
    st.markdown("All layers · Single threat score · Full report")
    st.success("✅ Active")

st.divider()
st.markdown("### 👈 Select a layer from the sidebar to begin scanning")

st.markdown("#### Platform Stats")
m1, m2, m3, m4, m5, m6 = st.columns(6)
with m1:
    st.metric("Active Layers", "7")
with m2:
    st.metric("Languages", "8")
with m3:
    st.metric("Network ROC-AUC", "0.9554")
with m4:
    st.metric("Malware Families", "10")
with m5:
    st.metric("Secret Patterns", "35+")
with m6:
    st.metric("Injection Types", "20+")

st.divider()
st.caption("GuardAI | Open source AI-powered defensive security | For authorized use only")
