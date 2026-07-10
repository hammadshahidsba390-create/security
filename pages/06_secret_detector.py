import streamlit as st
import re
import math
import zipfile
import io
from datetime import datetime

st.set_page_config(
    page_title="Secret Detector",
    page_icon="🔑",
    layout="wide"
)

st.markdown("# 🔑 Layer 6 — Secret & API Key Detector")
st.markdown("*Detects leaked credentials, API keys, tokens, and private keys in code and files*")
st.divider()

# --- Detection Patterns ---
SECRET_PATTERNS = [
    # Cloud providers
    ('AWS Access Key',        'CRITICAL', r'AKIA[0-9A-Z]{16}'),
    ('AWS Secret Key',        'CRITICAL', r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'),
    ('Google API Key',        'HIGH',     r'AIza[0-9A-Za-z\-_]{35}'),
    ('Google OAuth',          'HIGH',     r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    ('Azure Storage Key',     'CRITICAL', r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),

    # Version control
    ('GitHub Token',          'CRITICAL', r'ghp_[A-Za-z0-9]{36}'),
    ('GitHub OAuth',          'CRITICAL', r'gho_[A-Za-z0-9]{36}'),
    ('GitHub App Token',      'CRITICAL', r'(ghu|ghs|ghr)_[A-Za-z0-9]{36}'),
    ('GitLab Token',          'HIGH',     r'glpat-[A-Za-z0-9\-_]{20}'),

    # Payment
    ('Stripe Secret Key',     'CRITICAL', r'sk_live_[0-9a-zA-Z]{24,}'),
    ('Stripe Publishable',    'MODERATE', r'pk_live_[0-9a-zA-Z]{24,}'),
    ('PayPal/Braintree',      'CRITICAL', r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),

    # Communication
    ('Slack Bot Token',       'HIGH',     r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}'),
    ('Slack User Token',      'HIGH',     r'xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-f]{32}'),
    ('Slack Webhook',         'HIGH',     r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    ('Twilio Account SID',    'HIGH',     r'AC[a-zA-Z0-9]{32}'),
    ('Twilio Auth Token',     'CRITICAL', r'(?i)twilio.{0,20}["\']([a-f0-9]{32})["\']'),
    ('SendGrid API Key',      'HIGH',     r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),

    # Databases
    ('MongoDB URI',           'CRITICAL', r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\']+'),
    ('PostgreSQL URI',        'CRITICAL', r'postgresql://[^:]+:[^@]+@[^\s"\']+'),
    ('MySQL URI',             'CRITICAL', r'mysql://[^:]+:[^@]+@[^\s"\']+'),
    ('Redis URI',             'HIGH',     r'redis://:[^@]+@[^\s"\']+'),

    # Private keys
    ('RSA Private Key',       'CRITICAL', r'-----BEGIN RSA PRIVATE KEY-----'),
    ('Private Key',           'CRITICAL', r'-----BEGIN PRIVATE KEY-----'),
    ('EC Private Key',        'CRITICAL', r'-----BEGIN EC PRIVATE KEY-----'),
    ('PGP Private Key',       'CRITICAL', r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    ('SSH Private Key',       'CRITICAL', r'-----BEGIN OPENSSH PRIVATE KEY-----'),

    # AI/ML APIs
    ('OpenAI API Key',        'HIGH',     r'sk-[A-Za-z0-9]{48}'),
    ('Anthropic API Key',     'HIGH',     r'sk-ant-[A-Za-z0-9\-_]{95}'),
    ('HuggingFace Token',     'HIGH',     r'hf_[A-Za-z0-9]{37}'),

    # Other services
    ('Mailgun API Key',       'HIGH',     r'key-[0-9a-zA-Z]{32}'),
    ('NPM Token',             'HIGH',     r'npm_[A-Za-z0-9]{36}'),
    ('Docker Hub Token',      'HIGH',     r'dckr_pat_[A-Za-z0-9\-_]{27}'),
    ('Heroku API Key',        'HIGH',     r'[hH]eroku.{0,20}["\'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["\']'),

    # Generic patterns
    ('Hardcoded Password',    'HIGH',     r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']'),
    ('Hardcoded Secret',      'HIGH',     r'(?i)(secret|api_secret|client_secret)\s*=\s*["\'][^"\']{8,}["\']'),
    ('Hardcoded Token',       'MODERATE', r'(?i)(token|access_token|auth_token)\s*=\s*["\'][^"\']{16,}["\']'),
    ('Bearer Token',          'MODERATE', r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}'),
    ('Basic Auth in URL',     'HIGH',     r'https?://[^:]+:[^@]{6,}@'),
]

SEVERITY_COLORS = {
    'CRITICAL': ('🔴', '#ff4b4b'),
    'HIGH':     ('🟠', '#ff8c00'),
    'MODERATE': ('🟡', '#ffd700'),
    'LOW':      ('🟢', '#00d4aa'),
}

def calculate_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def is_likely_placeholder(value):
    placeholders = [
        'your_', 'YOUR_', 'example', 'EXAMPLE', 'xxx', 'XXX',
        'placeholder', 'changeme', 'replace', 'insert', 'dummy',
        '<', '>', 'todo', 'TODO', '****', '....'
    ]
    return any(p in value for p in placeholders)

def scan_content(content, filename=''):
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
            continue

        for name, severity, pattern in SECRET_PATTERNS:
            matches = re.finditer(pattern, line)
            for match in matches:
                value = match.group(0)

                # Skip placeholders
                if is_likely_placeholder(value):
                    continue

                # Calculate entropy for generic patterns
                entropy = calculate_entropy(value)

                # For generic password patterns, require higher entropy
                if name in ['Hardcoded Password', 'Hardcoded Secret',
                             'Hardcoded Token', 'Bearer Token']:
                    if entropy < 3.0:
                        continue

                # Redact the actual secret value for display
                if len(value) > 20:
                    display = value[:8] + '****' + value[-4:]
                else:
                    display = value[:4] + '****'

                findings.append({
                    'line':     line_num,
                    'type':     name,
                    'severity': severity,
                    'value':    display,
                    'entropy':  round(entropy, 2),
                    'context':  line.strip()[:100],
                    'file':     filename
                })

    return findings

def scan_zip(zip_bytes):
    all_findings = []
    skip_ext = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll',
                '.pth', '.pkl', '.bin', '.pyc'}

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if any(name.endswith(ext) for ext in skip_ext):
                continue
            if '__pycache__' in name or '.git/' in name:
                continue
            try:
                content = zf.read(name).decode('utf-8', errors='ignore')
                findings = scan_content(content, filename=name)
                all_findings.extend(findings)
            except Exception:
                continue

    return all_findings

# --- UI ---
tab1, tab2, tab3 = st.tabs([
    "📝 Paste Code",
    "📁 Upload File",
    "🗜️ Scan Project ZIP"
])

with tab1:
    code_input = st.text_area(
        "Paste code or configuration file content",
        height=250,
        placeholder='''# Example — paste any code here
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgresql://admin:password123@localhost/mydb"
STRIPE_SECRET = "sk_live_abc123xyz"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
'''
    )
    scan_btn = st.button("🔍 Scan for Secrets",
                          type="primary",
                          use_container_width=True,
                          key="paste_scan")

    if scan_btn and code_input.strip():
        findings = scan_content(code_input, 'pasted_code')
        if findings:
            critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
            high     = sum(1 for f in findings if f['severity'] == 'HIGH')

            st.error(f"🚨 Found **{len(findings)}** secrets — **{critical} CRITICAL**, **{high} HIGH**")

            for f in findings:
                icon, _ = SEVERITY_COLORS.get(f['severity'], ('⚪', '#fff'))
                with st.expander(
                    f"{icon} {f['severity']} — {f['type']} on line {f['line']}",
                    expanded=(f['severity'] == 'CRITICAL')
                ):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown(f"**Type:** {f['type']}")
                    with c2:
                        st.markdown(f"**Line:** {f['line']}")
                    with c3:
                        st.markdown(f"**Entropy:** {f['entropy']}")
                    st.code(f['context'], language='text')
                    st.warning(f"**Detected value:** `{f['value']}`")
                    st.error("**Action:** Rotate this credential immediately and remove from codebase")
        else:
            st.success("✅ No secrets detected")
    elif scan_btn:
        st.warning("Paste some code to scan")

with tab2:
    uploaded = st.file_uploader(
        "Upload any code or config file",
        type=['py', 'js', 'ts', 'env', 'txt', 'json',
              'yaml', 'yml', 'toml', 'cfg', 'ini', 'sh',
              'php', 'java', 'go', 'rb', 'cs', 'cpp', 'c']
    )

    if uploaded:
        content  = uploaded.read().decode('utf-8', errors='ignore')
        findings = scan_content(content, uploaded.name)

        st.info(f"Scanned: `{uploaded.name}` ({len(content)} bytes)")

        if findings:
            critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
            high     = sum(1 for f in findings if f['severity'] == 'HIGH')
            st.error(f"🚨 **{len(findings)} secrets found** — {critical} CRITICAL, {high} HIGH")

            for f in findings:
                icon, _ = SEVERITY_COLORS.get(f['severity'], ('⚪', '#fff'))
                with st.expander(
                    f"{icon} {f['severity']} — {f['type']} (line {f['line']})",
                    expanded=(f['severity'] == 'CRITICAL')
                ):
                    st.markdown(f"**File:** `{f['file']}`")
                    st.markdown(f"**Line:** {f['line']} | **Entropy:** {f['entropy']}")
                    st.code(f['context'], language='text')
                    st.warning(f"**Value:** `{f['value']}`")
                    st.error("**Action:** Rotate immediately")
        else:
            st.success("✅ No secrets found")

with tab3:
    st.markdown("Scan an entire project ZIP for secrets across all files")
    zip_file = st.file_uploader("Upload project .zip", type=['zip'])

    if zip_file:
        with st.spinner("Scanning all files in project..."):
            findings = scan_zip(zip_file.read())

        if findings:
            critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
            high     = sum(1 for f in findings if f['severity'] == 'HIGH')
            files_affected = len(set(f['file'] for f in findings))

            st.error(f"🚨 **{len(findings)} secrets** across **{files_affected} files**")

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Total Secrets", len(findings))
            with c2:
                st.metric("🔴 Critical", critical)
            with c3:
                st.metric("🟠 High", high)
            with c4:
                st.metric("Files Affected", files_affected)

            # Group by file
            from collections import defaultdict
            by_file = defaultdict(list)
            for f in findings:
                by_file[f['file']].append(f)

            for fname, file_findings in sorted(by_file.items()):
                with st.expander(f"📄 {fname} — {len(file_findings)} secrets"):
                    for f in file_findings:
                        icon, _ = SEVERITY_COLORS.get(f['severity'], ('⚪', '#fff'))
                        st.markdown(
                            f"{icon} **{f['severity']}** — {f['type']} "
                            f"(line {f['line']}): `{f['value']}`"
                        )

            # Download report
            import json
            report = {
                'scan_time': datetime.now().isoformat(),
                'total':     len(findings),
                'critical':  critical,
                'high':      high,
                'findings':  findings
            }
            st.download_button(
                "📥 Download Report",
                json.dumps(report, indent=2),
                file_name=f"guardai_secrets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        else:
            st.success("✅ No secrets found in project")

st.divider()
st.caption("GuardAI Layer 6 | Detects 35+ secret types | Entropy analysis | Never stores scanned content")
