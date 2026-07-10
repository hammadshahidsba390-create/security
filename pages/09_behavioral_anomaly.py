import streamlit as st
import math
import re
import json
import numpy as np
from datetime import datetime
from collections import Counter

st.set_page_config(
    page_title="Behavioral Anomaly Engine",
    page_icon="🧠",
    layout="wide"
)

st.markdown("# 🧠 Layer 9 — Behavioral Anomaly Engine")
st.markdown("*Detects anomalous patterns using statistical baselines — catches novel threats signatures miss*")
st.divider()

# --- Statistical Analysis Functions ---

def calculate_entropy(data):
    if not data:
        return 0.0
    counter = Counter(data)
    length  = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counter.values())

def calculate_byte_entropy(text):
    return calculate_entropy(text.encode('utf-8', errors='ignore'))

def analyze_code_structure(code):
    lines         = code.splitlines()
    non_empty     = [l for l in lines if l.strip()]
    total_chars   = len(code)
    total_lines   = len(lines)

    if total_chars == 0:
        return {}

    # Feature extraction
    features = {
        # Entropy features
        'char_entropy':         calculate_entropy(code),
        'byte_entropy':         calculate_byte_entropy(code),

        # Length features
        'total_chars':          total_chars,
        'total_lines':          total_lines,
        'avg_line_length':      np.mean([len(l) for l in non_empty]) if non_empty else 0,
        'max_line_length':      max([len(l) for l in lines]) if lines else 0,

        # Character distribution
        'uppercase_ratio':      sum(1 for c in code if c.isupper()) / total_chars,
        'digit_ratio':          sum(1 for c in code if c.isdigit()) / total_chars,
        'special_char_ratio':   sum(1 for c in code if not c.isalnum() and c not in ' \n\t') / total_chars,
        'space_ratio':          sum(1 for c in code if c == ' ') / total_chars,

        # Code-specific features
        'comment_ratio':        len([l for l in lines if l.strip().startswith(('#', '//', '/*', '*'))]) / max(total_lines, 1),
        'blank_line_ratio':     len([l for l in lines if not l.strip()]) / max(total_lines, 1),
        'indent_consistency':   _check_indent_consistency(lines),
        'long_line_ratio':      len([l for l in lines if len(l) > 100]) / max(total_lines, 1),
        'very_long_line_ratio': len([l for l in lines if len(l) > 200]) / max(total_lines, 1),

        # Suspicious patterns
        'base64_density':       len(re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', code)) / max(total_lines, 1),
        'hex_density':          len(re.findall(r'(0x[0-9a-fA-F]{4,}|\\x[0-9a-fA-F]{2})', code)) / max(total_chars, 1) * 100,
        'url_density':          len(re.findall(r'https?://', code)) / max(total_lines, 1),
        'ip_density':           len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', code)) / max(total_lines, 1),
        'eval_density':         len(re.findall(r'(?i)\b(eval|exec|system|shell_exec|popen)\s*\(', code)) / max(total_lines, 1),
        'obfuscation_score':    _calculate_obfuscation_score(code),
        'repetition_score':     _calculate_repetition_score(code),
        'random_naming_score':  _calculate_random_naming(code),
    }
    return features

def _check_indent_consistency(lines):
    indents = []
    for line in lines:
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent > 0:
                indents.append(indent)
    if not indents:
        return 1.0
    common = Counter(indents).most_common(1)[0][0]
    consistent = sum(1 for i in indents if i % common == 0)
    return consistent / len(indents)

def _calculate_obfuscation_score(code):
    score = 0.0
    # Long single-line code
    if any(len(l) > 500 for l in code.splitlines()):
        score += 0.3
    # High ratio of non-printable/special chars
    special = sum(1 for c in code if not c.isalnum() and c not in ' \n\t\r.,;:()[]{}"\'-_=+*/\\<>!@#$%^&|~`?')
    if len(code) > 0 and special / len(code) > 0.1:
        score += 0.3
    # Many string concatenations
    if len(re.findall(r'["\'][^"\']{0,5}["\'\+]\s*\+\s*["\']', code)) > 5:
        score += 0.2
    # Variable names that look random
    vars_found = re.findall(r'\b([a-z]{8,})\b', code)
    if vars_found:
        avg_entropy = np.mean([calculate_entropy(v) for v in vars_found[:20]])
        if avg_entropy > 3.2:
            score += 0.2
    return min(1.0, score)

def _calculate_repetition_score(code):
    words  = re.findall(r'\b\w+\b', code.lower())
    if not words:
        return 0.0
    counter = Counter(words)
    top_freq = counter.most_common(1)[0][1] / len(words)
    return min(1.0, top_freq * 10)

def _calculate_random_naming(code):
    identifiers = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{5,})\b', code)
    if not identifiers:
        return 0.0
    entropies = [calculate_entropy(i) for i in identifiers[:50]]
    avg = np.mean(entropies) if entropies else 0.0
    # Normal code: avg entropy ~2.5-3.0
    # Obfuscated: avg entropy >3.3
    return min(1.0, max(0.0, (avg - 2.5) / 1.0))

# --- Baseline profiles (learned from clean code) ---
BASELINES = {
    'Python': {
        'char_entropy':         (3.8, 0.4),
        'avg_line_length':      (35.0, 15.0),
        'uppercase_ratio':      (0.08, 0.05),
        'special_char_ratio':   (0.15, 0.08),
        'comment_ratio':        (0.15, 0.10),
        'long_line_ratio':      (0.05, 0.05),
        'base64_density':       (0.0, 0.05),
        'hex_density':          (0.01, 0.02),
        'eval_density':         (0.0, 0.01),
        'obfuscation_score':    (0.0, 0.15),
        'random_naming_score':  (0.2, 0.15),
    },
    'JavaScript': {
        'char_entropy':         (3.9, 0.4),
        'avg_line_length':      (40.0, 20.0),
        'uppercase_ratio':      (0.06, 0.04),
        'special_char_ratio':   (0.18, 0.08),
        'comment_ratio':        (0.10, 0.08),
        'long_line_ratio':      (0.08, 0.08),
        'base64_density':       (0.0, 0.05),
        'hex_density':          (0.01, 0.02),
        'eval_density':         (0.0, 0.01),
        'obfuscation_score':    (0.0, 0.15),
        'random_naming_score':  (0.2, 0.15),
    },
    'Generic': {
        'char_entropy':         (3.8, 0.5),
        'avg_line_length':      (40.0, 20.0),
        'uppercase_ratio':      (0.08, 0.06),
        'special_char_ratio':   (0.15, 0.10),
        'comment_ratio':        (0.10, 0.10),
        'long_line_ratio':      (0.05, 0.08),
        'base64_density':       (0.0, 0.05),
        'hex_density':          (0.01, 0.03),
        'eval_density':         (0.0, 0.02),
        'obfuscation_score':    (0.0, 0.20),
        'random_naming_score':  (0.2, 0.20),
    }
}

def detect_anomalies(features, language='Generic'):
    baseline  = BASELINES.get(language, BASELINES['Generic'])
    anomalies = []

    for feature, (mean, std) in baseline.items():
        if feature not in features:
            continue
        value = features[feature]
        if std == 0:
            continue
        z_score = abs(value - mean) / std

        if z_score > 3.0:
            severity = 'CRITICAL'
        elif z_score > 2.0:
            severity = 'HIGH'
        elif z_score > 1.5:
            severity = 'MODERATE'
        else:
            continue

        direction = 'higher' if value > mean else 'lower'
        anomalies.append({
            'feature':   feature,
            'severity':  severity,
            'value':     round(value, 4),
            'expected':  f"{mean:.2f} ± {std:.2f}",
            'z_score':   round(z_score, 2),
            'direction': direction,
            'message':   _get_anomaly_message(feature, direction, value)
        })

    return sorted(anomalies, key=lambda x: x['z_score'], reverse=True)

def _get_anomaly_message(feature, direction, value):
    messages = {
        'char_entropy':        f"Character entropy is {direction} than normal — {'possible encryption/encoding' if direction == 'higher' else 'unusually repetitive content'}",
        'avg_line_length':     f"Lines are {'unusually long — possible minification or obfuscation' if direction == 'higher' else 'unusually short'}",
        'uppercase_ratio':     f"{'High uppercase ratio — possible encoding or obfuscation' if direction == 'higher' else 'Low uppercase — unusual'}",
        'special_char_ratio':  f"{'High special character density — possible obfuscation' if direction == 'higher' else 'Very low special chars'}",
        'comment_ratio':       f"{'Very well commented — possibly auto-generated' if direction == 'higher' else 'No comments — suspicious for production code'}",
        'long_line_ratio':     f"{'Many long lines — possible minified/obfuscated code' if direction == 'higher' else 'Unusually short lines'}",
        'base64_density':      f"High Base64 string density — possible encoded payload",
        'hex_density':         f"High hexadecimal density — possible shellcode or encoded data",
        'eval_density':        f"High eval/exec usage — code execution risk",
        'obfuscation_score':   f"High obfuscation score — code structure is abnormal",
        'random_naming_score': f"{'Variable names appear random — possible AI-generated or obfuscated code' if direction == 'higher' else 'Very consistent naming'}",
    }
    return messages.get(feature, f"{feature} is {direction} than baseline")

def calculate_anomaly_risk(anomalies):
    if not anomalies:
        return 0
    score = 0
    for a in anomalies:
        if a['severity'] == 'CRITICAL': score += 25
        elif a['severity'] == 'HIGH':   score += 15
        else:                           score += 5
    return min(100, score)

SEVERITY_ICONS = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MODERATE': '🟡'
}

# --- UI ---
tab1, tab2 = st.tabs(["🔍 Analyze Code", "📊 Network Log Analysis"])

with tab1:
    st.markdown("### Code Behavioral Analysis")
    st.info("Paste any code — the engine compares its statistical profile against learned baselines to detect anomalies.")

    col1, col2 = st.columns([3, 1])
    with col1:
        code_input = st.text_area(
            "Paste code to analyze",
            height=300,
            placeholder="Paste any code here..."
        )
    with col2:
        language = st.selectbox("Language", ['Generic', 'Python', 'JavaScript'])
        st.markdown("**What it detects:**")
        st.markdown("- Obfuscated code")
        st.markdown("- Encoded payloads")
        st.markdown("- AI-generated malware")
        st.markdown("- Shellcode patterns")
        st.markdown("- Anomalous structure")

    analyze_btn = st.button("🧠 Analyze Behavior",
                             type="primary",
                             use_container_width=True)

    if analyze_btn and code_input.strip():
        with st.spinner("Computing statistical profile..."):
            features  = analyze_code_structure(code_input)
            anomalies = detect_anomalies(features, language)
            risk      = calculate_anomaly_risk(anomalies)

        st.divider()
        st.markdown("### 📊 Analysis Results")

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Risk Score", f"{risk}/100")
        with c2:
            st.metric("Anomalies", len(anomalies))
        with c3:
            st.metric("Char Entropy", f"{features.get('char_entropy', 0):.2f}")
        with c4:
            st.metric("Obfuscation Score", f"{features.get('obfuscation_score', 0):.2f}")

        if risk >= 70:
            st.error("🚨 HIGH ANOMALY — Code behavior deviates significantly from baseline. Possible malware or obfuscation.")
        elif risk >= 40:
            st.warning("⚠️ MODERATE ANOMALY — Several unusual patterns detected. Manual review recommended.")
        elif risk > 0:
            st.info("ℹ️ LOW ANOMALY — Minor deviations from baseline.")
        else:
            st.success("✅ NORMAL — Code behavior matches baseline profile.")

        if anomalies:
            st.markdown("### Detected Anomalies")
            for a in anomalies:
                icon = SEVERITY_ICONS.get(a['severity'], '⚪')
                with st.expander(
                    f"{icon} {a['severity']} — {a['feature']} (z-score: {a['z_score']})",
                    expanded=(a['severity'] == 'CRITICAL')
                ):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.metric("Observed", a['value'])
                    with c2:
                        st.metric("Expected", a['expected'])
                    with c3:
                        st.metric("Z-Score", a['z_score'])
                    st.warning(a['message'])

        # Feature breakdown
        with st.expander("📈 Full Statistical Profile"):
            profile_data = {k: round(v, 4) if isinstance(v, float) else v
                           for k, v in features.items()
                           if k not in ['total_chars', 'total_lines']}
            for k, v in profile_data.items():
                st.markdown(f"**{k}:** `{v}`")

with tab2:
    st.markdown("### Network Log Behavioral Analysis")
    st.info("Paste network logs or connection data to detect anomalous traffic patterns.")

    log_input = st.text_area(
        "Paste network logs (one connection per line)",
        height=250,
        placeholder="""192.168.1.1 -> 8.8.8.8:443 HTTPS 1.2KB
192.168.1.1 -> 8.8.8.8:443 HTTPS 0.8KB
192.168.1.1 -> 192.168.1.50:22 SSH 0.1KB
192.168.1.1 -> 185.220.101.1:4444 TCP 50KB"""
    )

    analyze_log_btn = st.button("🧠 Analyze Network Behavior",
                                 type="primary",
                                 use_container_width=True,
                                 key="log_btn")

    if analyze_log_btn and log_input.strip():
        lines    = [l.strip() for l in log_input.splitlines() if l.strip()]
        findings = []

        # Extract features from logs
        ports    = re.findall(r':(\d+)', log_input)
        sizes    = re.findall(r'(\d+\.?\d*)\s*KB', log_input)
        ips      = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_input)

        suspicious_ports = {'4444', '1337', '31337', '8080', '9090', '6666', '6667'}
        private_ranges   = ['192.168.', '10.', '172.16.', '172.17.']

        for line in lines:
            line_ports = re.findall(r':(\d+)', line)
            for port in line_ports:
                if port in suspicious_ports:
                    findings.append({
                        'severity': 'CRITICAL',
                        'type':     'Suspicious Port',
                        'message':  f"Connection to port {port} — common C2/malware port",
                        'line':     line
                    })

            # Large data transfers
            line_sizes = re.findall(r'(\d+\.?\d*)\s*KB', line)
            for size in line_sizes:
                if float(size) > 10:
                    findings.append({
                        'severity': 'HIGH',
                        'type':     'Large Transfer',
                        'message':  f"Unusually large transfer: {size}KB — possible data exfiltration",
                        'line':     line
                    })

            # External IP with high port
            ext_ips = re.findall(r'-> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', line)
            for ip, port in ext_ips:
                is_private = any(ip.startswith(r) for r in private_ranges)
                if not is_private and int(port) > 1024 and port not in {'8080', '8443', '443', '80'}:
                    findings.append({
                        'severity': 'MODERATE',
                        'type':     'Unusual External Connection',
                        'message':  f"Connection to external IP {ip} on non-standard port {port}",
                        'line':     line
                    })

        if findings:
            critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
            st.error(f"🚨 {len(findings)} anomalies — {critical} CRITICAL")
            for f in findings:
                icon = SEVERITY_ICONS.get(f['severity'], '⚪')
                with st.expander(f"{icon} {f['severity']} — {f['type']}"):
                    st.markdown(f"**{f['message']}**")
                    st.code(f['line'])
        else:
            st.success("✅ Network behavior appears normal")

st.divider()
st.caption("GuardAI Layer 9 | Statistical anomaly detection | Z-score baseline comparison | No signatures needed")
