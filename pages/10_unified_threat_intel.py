import streamlit as st
import requests
import json
import re
import math
from datetime import datetime
from collections import Counter

st.set_page_config(page_title="Unified Threat Intelligence", page_icon="🛡️", layout="wide")

st.markdown("# 🛡️ Layer 10 — Unified Threat Intelligence")
st.markdown("*All 7 layers combined — one input, one threat score, one report*")
st.divider()

def calculate_entropy(data):
    if not data: return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counter.values())

def is_placeholder(value):
    return any(p in value for p in ['your_','YOUR_','example','EXAMPLE','xxx','placeholder','changeme','<','>','****','....'])

CODE_VULNS = [
    ('SQL Injection',      'CRITICAL', 'SELECT.*FROM.*WHERE.*=.*\\+'),
    ('Command Injection',  'CRITICAL', 'os\\.system|shell=True|subprocess'),
    ('Hardcoded Password', 'HIGH',     'password\\s*=\\s*["\'][^"\']{6,}["\']'),
    ('Weak Crypto',        'HIGH',     '\\bmd5\\b|\\bsha1\\b'),
    ('XSS',                'HIGH',     'innerHTML|document\\.write'),
    ('Debug Mode',         'MODERATE', 'debug\\s*=\\s*True|DEBUG\\s*=\\s*True'),
]

def scan_code_vulns(code):
    findings = []
    for name, severity, pattern in CODE_VULNS:
        try:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append({'type': name, 'severity': severity, 'layer': 1})
        except Exception:
            pass
    return findings

def scan_cves(text):
    findings = []
    packages = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*[=~><!]+\s*([^\s,;]+)', line)
        if match:
            packages.append({'name': match.group(1), 'version': match.group(2)})
    for pkg in packages[:10]:
        try:
            resp = requests.post(
                'https://api.osv.dev/v1/query',
                json={'package': {'name': pkg['name'], 'ecosystem': 'PyPI'}, 'version': pkg['version']},
                timeout=5
            )
            if resp.status_code == 200:
                for v in resp.json().get('vulns', []):
                    sev = v.get('database_specific', {}).get('severity', 'MODERATE').upper()
                    findings.append({
                        'type': 'CVE in ' + pkg['name'] + ' ' + pkg['version'],
                        'severity': sev if sev in ['CRITICAL','HIGH','MODERATE','LOW'] else 'MODERATE',
                        'layer': 5,
                        'detail': v.get('summary', '')[:80]
                    })
        except Exception:
            pass
    return findings

SECRET_PATTERNS = [
    ('AWS Access Key',   'CRITICAL', 'AKIA[0-9A-Z]{16}'),
    ('GitHub Token',     'CRITICAL', 'ghp_[A-Za-z0-9]{36}'),
    ('OpenAI Key',       'HIGH',     'sk-[A-Za-z0-9]{48}'),
    ('MongoDB URI',      'CRITICAL', 'mongodb://[^:]+:[^@]+@'),
    ('Private Key',      'CRITICAL', '-----BEGIN.*PRIVATE KEY-----'),
    ('Stripe Key',       'CRITICAL', 'sk_live_[0-9a-zA-Z]{24,}'),
    ('Hardcoded Secret', 'HIGH',     'secret\\s*=\\s*["\'][^"\']{8,}["\']'),
]

def scan_secrets(text):
    findings = []
    for name, severity, pattern in SECRET_PATTERNS:
        try:
            for m in re.findall(pattern, text):
                if not is_placeholder(str(m)):
                    findings.append({'type': 'Secret: ' + name, 'severity': severity, 'layer': 6})
        except Exception:
            pass
    return findings

INJECTION_PATTERNS = [
    ('Instruction Override', 'CRITICAL', 'ignore.{0,20}previous.{0,20}instructions'),
    ('Jailbreak DAN',        'CRITICAL', 'DAN|do anything now|jailbreak'),
    ('System Prompt Leak',   'HIGH',     'reveal.{0,20}system.{0,20}prompt'),
    ('Role Override',        'HIGH',     'you are now|act as|pretend to be'),
]

def scan_injections(text):
    findings = []
    for name, severity, pattern in INJECTION_PATTERNS:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append({'type': 'Prompt Injection: ' + name, 'severity': severity, 'layer': 7})
        except Exception:
            pass
    return findings

def scan_anomalies(text):
    findings = []
    if not text: return findings
    entropy = calculate_entropy(text)
    if entropy > 5.0:
        findings.append({'type': 'High Entropy Content', 'severity': 'HIGH', 'layer': 9})
    if len(re.findall(r'\\x[0-9a-fA-F]{2}', text)) > 5:
        findings.append({'type': 'High Hex Density (Shellcode)', 'severity': 'CRITICAL', 'layer': 9})
    if len(re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)) > 2:
        findings.append({'type': 'High Base64 Density', 'severity': 'HIGH', 'layer': 9})
    if len(re.findall(r'\beval\b|\bexec\b|\bsystem\b', text, re.IGNORECASE)) > 1:
        findings.append({'type': 'Multiple Code Execution Calls', 'severity': 'CRITICAL', 'layer': 9})
    return findings

def check_threat_intel(text):
    findings = []
    bad_ranges = ['185.220.', '194.165.', '45.142.', '91.108.']
    for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)[:5]:
        if any(ip.startswith(b) for b in bad_ranges):
            findings.append({'type': 'Known Malicious IP: ' + ip, 'severity': 'CRITICAL', 'layer': 10})
    for domain in re.findall(r'\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})\b', text)[:10]:
        if any(domain.endswith(t) for t in ['.xyz','.top','.click','.download']):
            findings.append({'type': 'Suspicious Domain: ' + domain, 'severity': 'HIGH', 'layer': 10})
    return findings

SEVERITY_WEIGHTS = {'CRITICAL': 25, 'HIGH': 15, 'MODERATE': 8, 'LOW': 3}
LAYER_NAMES = {1:'🔍 Code Scanner', 5:'📦 CVE Scanner', 6:'🔑 Secret Detector', 7:'🤖 Prompt Injection', 9:'🧠 Behavioral Anomaly', 10:'🌐 Threat Intel'}

def calculate_threat_score(findings):
    return min(100, sum(SEVERITY_WEIGHTS.get(f['severity'], 5) for f in findings))

def get_threat_level(score):
    if score >= 75: return ('CRITICAL', '🔴', 'Immediate action required')
    if score >= 50: return ('HIGH',     '🟠', 'Urgent review needed')
    if score >= 25: return ('MODERATE', '🟡', 'Investigation recommended')
    if score > 0:   return ('LOW',      '🟢', 'Monitor closely')
    return                 ('SAFE',     '✅', 'No threats detected')

st.markdown("### 🎯 Unified Scan — All Layers at Once")
st.info("Paste any content — code, config, logs, or text. All active layers scan simultaneously.")

input_text = st.text_area("Input to scan", height=300,
    placeholder="Paste code, config files, logs, or any text here...")

col1, col2 = st.columns(2)
with col1:
    scan_btn = st.button("🚀 Run Unified Scan", type="primary", use_container_width=True)
with col2:
    cve_toggle = st.checkbox("Include live CVE lookup (slower)", value=False)

if scan_btn and input_text.strip():
    with st.spinner("Running all layers..."):
        all_findings = []
        progress = st.progress(0)
        all_findings.extend(scan_code_vulns(input_text)); progress.progress(20)
        if cve_toggle:
            all_findings.extend(scan_cves(input_text))
        progress.progress(40)
        all_findings.extend(scan_secrets(input_text)); progress.progress(55)
        all_findings.extend(scan_injections(input_text)); progress.progress(70)
        all_findings.extend(scan_anomalies(input_text)); progress.progress(85)
        all_findings.extend(check_threat_intel(input_text)); progress.progress(100)
        progress.empty()

    score        = calculate_threat_score(all_findings)
    threat_level = get_threat_level(score)
    critical     = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
    high         = sum(1 for f in all_findings if f['severity'] == 'HIGH')
    layers_hit   = len(set(f.get('layer') for f in all_findings))

    st.divider()
    st.markdown(f"## {threat_level[1]} Threat Level: {threat_level[0]}")
    st.markdown(f"*{threat_level[2]}*")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: st.metric("Threat Score",     f"{score}/100")
    with m2: st.metric("Total Findings",   len(all_findings))
    with m3: st.metric("Critical",         critical)
    with m4: st.metric("High",             high)
    with m5: st.metric("Layers Triggered", f"{layers_hit}/6")

    if score >= 75:   st.error(f"🚨 CRITICAL THREAT — {critical} critical findings. Do not deploy.")
    elif score >= 50: st.error("🟠 HIGH THREAT — Significant security issues detected.")
    elif score >= 25: st.warning("⚠️ MODERATE THREAT — Review before proceeding.")
    elif score > 0:   st.info("ℹ️ LOW THREAT — Minor issues detected.")
    else:             st.success("✅ CLEAN — No threats detected.")

    if all_findings:
        st.divider()
        st.markdown("### 📋 Findings by Layer")
        by_layer = {}
        for f in all_findings:
            by_layer.setdefault(f.get('layer', 0), []).append(f)
        for layer_num in sorted(by_layer.keys()):
            lf   = by_layer[layer_num]
            lc   = sum(1 for f in lf if f['severity'] == 'CRITICAL')
            name = LAYER_NAMES.get(layer_num, 'Layer ' + str(layer_num))
            with st.expander(f"{name} — {len(lf)} findings ({lc} critical)", expanded=(lc > 0)):
                for f in lf:
                    icon = {'CRITICAL':'🔴','HIGH':'🟠','MODERATE':'🟡'}.get(f['severity'],'⚪')
                    st.markdown(f"{icon} **{f['severity']}** — {f['type']}")
                    if f.get('detail'): st.caption(f['detail'])

    st.divider()
    st.markdown("### 🔧 Recommended Actions")
    if critical > 0: st.error("🔴 IMMEDIATE — Rotate exposed credentials and block critical findings")
    if high > 0:     st.warning("🟠 URGENT — Fix HIGH severity issues within 24 hours")
    st.info("ℹ️ Run individual layer scans for detailed remediation guidance")

    report = {'scan_time': datetime.now().isoformat(), 'threat_score': score,
              'threat_level': threat_level[0], 'findings': all_findings}
    st.download_button("📥 Download Threat Report (JSON)", json.dumps(report, indent=2),
        file_name=f"guardai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json", use_container_width=True)

elif scan_btn:
    st.warning("Paste some content to scan.")

st.divider()
st.markdown("### 🌐 Live Threat Intelligence Feeds")
c1, c2, c3 = st.columns(3)
with c1:
    st.markdown("**abuse.ch**")
    st.markdown("- [MalwareBazaar](https://bazaar.abuse.ch)")
    st.markdown("- [URLhaus](https://urlhaus.abuse.ch)")
with c2:
    st.markdown("**Public Intel**")
    st.markdown("- [AlienVault OTX](https://otx.alienvault.com)")
    st.markdown("- [VirusTotal](https://virustotal.com)")
with c3:
    st.markdown("**CVE Databases**")
    st.markdown("- [OSV.dev](https://osv.dev)")
    st.markdown("- [NVD NIST](https://nvd.nist.gov)")

st.divider()
st.caption("GuardAI Layer 10 | Unified Threat Intelligence | All layers combined | Single threat score")# placeholder
