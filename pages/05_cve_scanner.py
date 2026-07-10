import streamlit as st
import requests
import json
import re
from datetime import datetime

st.set_page_config(
    page_title="CVE Scanner",
    page_icon="🔍",
    layout="wide"
)

st.markdown("# 🔍 Layer 5 — CVE Dependency Scanner")
st.markdown("*Real-time vulnerability scanning via OSV.dev | Covers PyPI, npm, Maven, Go, Ruby, Rust*")
st.divider()

SEVERITY_COLORS = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MODERATE': '🟡',
    'LOW':      '🟢',
    'UNKNOWN':  '⚪'
}

ECOSYSTEM_MAP = {
    'requirements.txt': 'PyPI',
    'package.json':     'npm',
    'pom.xml':          'Maven',
    'go.mod':           'Go',
    'Gemfile':          'RubyGems',
    'Cargo.toml':       'crates.io',
}

def parse_requirements(content):
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Handle: package==1.0.0, package>=1.0.0, package~=1.0.0
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*[=~><!]+\s*([^\s,;]+)', line)
        if match:
            packages.append({
                'name':    match.group(1).strip(),
                'version': match.group(2).strip()
            })
        elif re.match(r'^[a-zA-Z0-9_\-\.]+$', line):
            packages.append({'name': line, 'version': None})
    return packages

def parse_package_json(content):
    packages = []
    try:
        data = json.loads(content)
        for section in ['dependencies', 'devDependencies']:
            for name, version in data.get(section, {}).items():
                clean = re.sub(r'^[\^~>=<]', '', version).strip()
                packages.append({'name': name, 'version': clean})
    except Exception:
        pass
    return packages

def parse_go_mod(content):
    packages = []
    for line in content.splitlines():
        line = line.strip()
        match = re.match(r'^([^\s]+)\s+v([^\s]+)', line)
        if match:
            packages.append({
                'name':    match.group(1),
                'version': match.group(2)
            })
    return packages

def query_osv(name, version, ecosystem):
    try:
        payload = {
            'package': {'name': name, 'ecosystem': ecosystem}
        }
        if version:
            payload['version'] = version

        resp = requests.post(
            'https://api.osv.dev/v1/query',
            json=payload,
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json().get('vulns', [])
    except Exception:
        pass
    return []

def get_severity(vuln):
    db = vuln.get('database_specific', {})
    sev = db.get('severity', '')
    if sev:
        return sev.upper()
    # Check CVSS score
    for s in vuln.get('severity', []):
        score_str = s.get('score', '')
        match = re.search(r'(\d+\.\d+)$', score_str)
        if match:
            score = float(match.group(1))
            if score >= 9.0: return 'CRITICAL'
            if score >= 7.0: return 'HIGH'
            if score >= 4.0: return 'MODERATE'
            return 'LOW'
    return 'UNKNOWN'

def get_fix_version(vuln):
    for affected in vuln.get('affected', []):
        for r in affected.get('ranges', []):
            for event in r.get('events', []):
                if 'fixed' in event:
                    return event['fixed']
    return None

def get_cve_ids(vuln):
    aliases = vuln.get('aliases', [])
    return [a for a in aliases if a.startswith('CVE-')]

# --- UI ---
tab1, tab2 = st.tabs(["📁 Upload File", "✏️ Paste Content"])

with tab1:
    uploaded = st.file_uploader(
        "Upload dependency file",
        type=['txt', 'json', 'mod', 'toml', 'xml'],
        help="requirements.txt, package.json, go.mod, Cargo.toml, pom.xml"
    )
    ecosystem_override = st.selectbox(
        "Ecosystem (auto-detected from filename)",
        ['Auto-detect', 'PyPI', 'npm', 'Go', 'Maven', 'RubyGems', 'crates.io']
    )
    scan_btn = st.button("🔍 Scan Dependencies", type="primary",
                          use_container_width=True, key="upload_scan")

    if scan_btn and uploaded:
        content   = uploaded.read().decode('utf-8', errors='ignore')
        fname     = uploaded.name.lower()
        ecosystem = ECOSYSTEM_MAP.get(fname, 'PyPI')
        if ecosystem_override != 'Auto-detect':
            ecosystem = ecosystem_override

        if 'requirements' in fname or fname.endswith('.txt'):
            packages = parse_requirements(content)
        elif fname == 'package.json':
            packages = parse_package_json(content)
        elif fname == 'go.mod':
            packages = parse_go_mod(content)
        else:
            packages = parse_requirements(content)

        st.info(f"Found **{len(packages)}** packages in `{uploaded.name}` ({ecosystem})")

        if packages:
            progress = st.progress(0)
            status   = st.empty()
            results  = []

            for i, pkg in enumerate(packages):
                status.text(f"Scanning {pkg['name']}...")
                vulns = query_osv(pkg['name'], pkg['version'], ecosystem)
                if vulns:
                    results.append({
                        'package': pkg['name'],
                        'version': pkg['version'],
                        'vulns':   vulns
                    })
                progress.progress((i + 1) / len(packages))

            status.text("Scan complete.")
            progress.empty()

            # Summary metrics
            total_vulns = sum(len(r['vulns']) for r in results)
            critical    = sum(
                1 for r in results for v in r['vulns']
                if get_severity(v) == 'CRITICAL'
            )
            high = sum(
                1 for r in results for v in r['vulns']
                if get_severity(v) == 'HIGH'
            )

            st.divider()
            st.markdown("## 📊 Scan Results")

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Packages Scanned", len(packages))
            with c2:
                st.metric("Vulnerable Packages", len(results))
            with c3:
                st.metric("Total CVEs Found", total_vulns)
            with c4:
                score = max(0, 100 - (critical*20) - (high*10) - (total_vulns*2))
                st.metric("Security Score", f"{score}/100")

            if critical > 0:
                st.error(f"🔴 {critical} CRITICAL vulnerabilities found — patch immediately")
            elif high > 0:
                st.warning(f"🟠 {high} HIGH vulnerabilities found — patch soon")
            elif total_vulns > 0:
                st.warning(f"🟡 {total_vulns} vulnerabilities found")
            else:
                st.success("✅ No known vulnerabilities found")

            # Detailed findings
            if results:
                st.markdown("### Vulnerable Packages")
                for r in results:
                    pkg_name = r['package']
                    pkg_ver  = r['version'] or 'unknown'
                    num_v    = len(r['vulns'])

                    with st.expander(
                        f"📦 {pkg_name} {pkg_ver} — {num_v} vulnerability/ies",
                        expanded=(num_v > 0)
                    ):
                        for vuln in r['vulns']:
                            severity = get_severity(vuln)
                            icon     = SEVERITY_COLORS.get(severity, '⚪')
                            fix_ver  = get_fix_version(vuln)
                            cve_ids  = get_cve_ids(vuln)
                            summary  = vuln.get('summary', 'No summary available')

                            st.markdown(f"**{icon} {severity}** — {summary}")

                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.markdown(f"**ID:** `{vuln.get('id', 'N/A')}`")
                            with col2:
                                if cve_ids:
                                    st.markdown(f"**CVE:** `{cve_ids[0]}`")
                            with col3:
                                if fix_ver:
                                    st.markdown(f"**Fix:** upgrade to `{fix_ver}`")
                                else:
                                    st.markdown("**Fix:** No fix available yet")

                            if vuln.get('details'):
                                details = vuln['details'][:300] + '...' \
                                    if len(vuln.get('details','')) > 300 \
                                    else vuln.get('details','')
                                st.caption(details)
                            st.markdown("---")

                # Download report
                report = {
                    'scan_time':         datetime.now().isoformat(),
                    'file':              uploaded.name,
                    'ecosystem':         ecosystem,
                    'packages_scanned':  len(packages),
                    'vulnerable':        len(results),
                    'total_cves':        total_vulns,
                    'findings':          [
                        {
                            'package': r['package'],
                            'version': r['version'],
                            'vulnerabilities': [
                                {
                                    'id':       v.get('id'),
                                    'summary':  v.get('summary'),
                                    'severity': get_severity(v),
                                    'fix':      get_fix_version(v),
                                    'cves':     get_cve_ids(v)
                                }
                                for v in r['vulns']
                            ]
                        }
                        for r in results
                    ]
                }
                st.download_button(
                    "📥 Download JSON Report",
                    json.dumps(report, indent=2),
                    file_name=f"guardai_cve_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )

with tab2:
    st.markdown("### Paste dependency content directly")
    ecosystem2 = st.selectbox(
        "Ecosystem",
        ['PyPI', 'npm', 'Go', 'Maven', 'RubyGems', 'crates.io'],
        key="eco2"
    )
    content2 = st.text_area(
        "Paste requirements.txt or package.json content",
        height=200,
        placeholder="requests==2.25.0\nnumpy==1.21.0\nflask==1.1.2"
    )
    scan_btn2 = st.button("🔍 Scan", type="primary",
                           use_container_width=True, key="paste_scan")

    if scan_btn2 and content2.strip():
        if ecosystem2 == 'npm':
            try:
                packages2 = parse_package_json(content2)
            except Exception:
                packages2 = parse_requirements(content2)
        else:
            packages2 = parse_requirements(content2)

        st.info(f"Found **{len(packages2)}** packages")
        progress2 = st.progress(0)
        results2  = []

        for i, pkg in enumerate(packages2):
            vulns = query_osv(pkg['name'], pkg['version'], ecosystem2)
            if vulns:
                results2.append({
                    'package': pkg['name'],
                    'version': pkg['version'],
                    'vulns':   vulns
                })
            progress2.progress((i + 1) / len(packages2))

        total2 = sum(len(r['vulns']) for r in results2)
        if results2:
            st.warning(f"Found **{total2}** vulnerabilities in **{len(results2)}** packages")
            for r in results2:
                with st.expander(f"📦 {r['package']} {r['version']}"):
                    for v in r['vulns']:
                        sev  = get_severity(v)
                        icon = SEVERITY_COLORS.get(sev, '⚪')
                        fix  = get_fix_version(v)
                        st.markdown(f"**{icon} {sev}** — {v.get('summary','')}")
                        if fix:
                            st.success(f"Fix: upgrade to `{fix}`")
                        st.markdown("---")
        else:
            st.success("✅ No known vulnerabilities found")

st.divider()
st.caption("GuardAI Layer 5 | Powered by OSV.dev | Covers PyPI · npm · Go · Maven · RubyGems · crates.io")
