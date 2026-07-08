import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import torch
import torch.nn as nn
import joblib
import os

st.set_page_config(
    page_title="Network Monitor",
    page_icon="🌐",
    layout="wide"
)

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class GuardAILSTM(nn.Module):
    def __init__(self, input_size, hidden_size=96, num_layers=2):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers,
                            batch_first=True, dropout=0.3)
        self.fc1 = nn.Linear(hidden_size, 32)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)
        self.fc2 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(device)
        out, _ = self.lstm(x, (h0, c0))
        out = out[:, -1, :]
        return self.sigmoid(self.fc2(self.dropout(self.relu(self.fc1(out)))))

@st.cache_resource
def load_network_model():
    from pathlib import Path
    BASE_DIR = Path(__file__).resolve().parent.parent
    scaler_path   = str(BASE_DIR / 'model/network/guardai_scaler.pkl')
    features_path = str(BASE_DIR / 'model/network/guardai_scaler_features.pkl')
    model_path    = str(BASE_DIR / 'model/network/guardai_lstm_model.pth')
    if not all(os.path.exists(p) for p in [scaler_path, features_path, model_path]):
        return None, None, None
    scaler   = joblib.load(scaler_path)
    features = joblib.load(features_path)
    model    = GuardAILSTM(input_size=len(features)).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device, weights_only=True))
    model.eval()
    return model, scaler, features

THRESHOLD = 0.85

st.markdown("# 🌐 Layer 2 — Network Intrusion Detection")
st.markdown("*LSTM trained on CIC-IDS2018 | ROC-AUC: 0.9554 | 100% attack recall*")
st.divider()

model, scaler, feature_cols = load_network_model()

if model is None:
    st.warning("Network model files not found in `model/network/`.")
    st.markdown("**Required architecture mapping location:**")
    st.code("model/network/guardai_lstm_model.pth\nmodel/network/guardai_scaler.pkl\nmodel/network/guardai_scaler_features.pkl")
    st.info("Ensure your downloaded assets are placed in this directory.")
    st.stop()

st.success(f"✅ LSTM engine initialized | Target Vector Dev: `{device}` | Threshold: `{THRESHOLD}`")

uploaded = st.file_uploader(
    "Upload network traffic CSV (CIC-IDS2018 format)",
    type=["csv"]
)

if uploaded:
    with st.spinner("Analyzing traffic flows..."):
        df = pd.read_csv(uploaded, low_memory=False)
        df.columns = df.columns.str.strip()
        df = df[df['Flow Duration'] != 'Flow Duration']
        df = df[~df.isin(['Flow Duration']).any(axis=1)]

        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # Convert all columns to numeric before scaling
        drop_cols_local = ['Timestamp', 'Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Label']
        for col in df.columns:
            if col not in drop_cols_local:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        df.fillna(0, inplace=True)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        drop_cols = ['Timestamp', 'Flow ID', 'Src IP', 'Dst IP', 'Label']
        X_raw = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')
        X_raw = X_raw.reindex(columns=feature_cols, fill_value=0)
        X_scaled = scaler.transform(X_raw)

        time_steps = 10
        X_seq = np.array([X_scaled[i:i+time_steps]
                          for i in range(len(X_scaled) - time_steps)])

        preds = []
        with torch.no_grad():
            tensor = torch.tensor(X_seq, dtype=torch.float32).to(device)
            for i in range(0, len(tensor), 512):
                out = model(tensor[i:i+512]).cpu().numpy()
                preds.extend(out.flatten())

        preds  = np.array(preds)
        labels = (preds >= THRESHOLD).astype(int)

    total   = len(labels)
    attacks = int(labels.sum())
    benign  = total - attacks

    st.markdown("## 📊 Results")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Flows", f"{total:,}")
    with c2:
        st.metric("🚨 Attacks Detected", f"{attacks:,}",
                  delta=f"{attacks/total*100:.1f}%", delta_color="inverse")
    with c3:
        st.metric("✅ Benign Flows", f"{benign:,}")
    with c4:
        avg_conf = preds[labels==1].mean() if attacks > 0 else 0
        st.metric("Avg Confidence", f"{avg_conf:.1%}")

    col1, col2 = st.columns(2)
    with col1:
        fig = go.Figure(go.Pie(
            labels=["Benign", "Attack"],
            values=[benign, attacks],
            hole=0.5,
            marker_colors=["#00d4aa", "#ff4b4b"]
        ))
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                          font_color="white", height=300,
                          title="Traffic Breakdown")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        fig2 = px.histogram(x=preds, nbins=50,
                            color_discrete_sequence=["#0f3460"],
                            title="Confidence Distribution")
        fig2.add_vline(x=THRESHOLD, line_dash="dash", line_color="#ff4b4b",
                       annotation_text=f"Threshold {THRESHOLD}")
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                           plot_bgcolor="rgba(0,0,0,0)",
                           font_color="white", height=300)
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("### Flow-Level Results")
    result_df = df.iloc[time_steps:time_steps+len(labels)].copy()
    result_df['Confidence'] = preds
    result_df['Verdict']    = np.where(labels==1, "🚨 ATTACK", "✅ Benign")
    show_cols = ['Verdict', 'Confidence']
    if 'Src IP' in result_df.columns: show_cols.insert(0, 'Src IP')
    if 'Dst IP' in result_df.columns: show_cols.insert(1, 'Dst IP')
    if 'Label'  in result_df.columns: show_cols.append('Label')
    st.dataframe(result_df[show_cols].head(500), use_container_width=True)

    csv_out = result_df[show_cols].to_csv(index=False)
    st.download_button("📥 Download Report CSV", csv_out,
                       file_name="guardai_network_report.csv", mime="text/csv")
else:
    st.info("👆 Upload a CIC-IDS2018 format CSV to scan network traffic.")
