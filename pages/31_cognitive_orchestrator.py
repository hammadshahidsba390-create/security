import streamlit as st
import json
import re
import math
import time
import requests
from datetime import datetime
from collections import Counter, defaultdict
from itertools import combinations

st.set_page_config(
    page_title="Cognitive Orchestrator",
    page_icon="🧠",
    layout="wide"
)

st.markdown("# 🧠 Layer 31 — Cognitive Security Orchestrator")
st.markdown("*Bayesian signal correlation across all layers — finds attacks that individual layers miss*")
st.divider()

# ── Bayesian Engine ──────────────────────────────────────────────────────────

BASE_ATTACK_RATE = 0.02  # 2% of inputs are attacks (conservative prior)

LAYER_PRIORS = {
    1:  {'name': '🔍 Code Scanner',        'P_signal_given_attack': 0.75, 'P_signal_given_benign': 0.05},
    2:  {'name': '🌐 Network IDS',         'P_signal_given_attack': 0.90, 'P_signal_given_benign': 0.02},
    3:  {'name': '🦠 Malware Detector',    'P_signal_given_attack': 0.77, 'P_signal_given_benign': 0.10},
    5:  {'name': '📦 CVE Scanner',         'P_signal_given_attack': 0.60, 'P_signal_given_benign': 0.20},
    6:  {'name': '🔑 Secret Detector',     'P_signal_given_attack': 0.85, 'P_signal_given_benign': 0.03},
    7:  {'name': '🤖 Prompt Injection',    'P_signal_given_attack': 0.88, 'P_signal_given_benign': 0.02},
    9:  {'name': '🧠 Anomaly Engine',      'P_signal_given_attack': 0.70, 'P_signal_given_benign': 0.15},
    10: {'name': '🌐 Threat Intel',        'P_signal_given_attack': 0.92, 'P_signal_given_benign': 0.01},
}

CORRELATION_MATRIX = {
    (1, 6):   3.5,
    (2, 6):   4.0,
    (2, 7):   3.0,
    (6, 7):   2.5,
    (1, 2):   2.8,
    (5, 1):   2.0,
    (9, 2):   3.2,
    (9, 7):   2.8,
    (6, 10):  4.5,
    (2, 10):  4.0,
    (1, 7):   2.5,
    (5, 2):   2.2,
    (3, 6):   3.0,
    (3, 9):   2.5,
    (1, 9):   2.2,
    (7, 10):  3.5,
}

ATTACK_SCENARIOS = {
    frozenset([2, 6, 10]): {
        'name':        'Active Data Exfiltration',
        'description': 'Network attack + exposed credentials + malicious IP — attacker is actively stealing data RIGHT NOW',
        'severity':    'CRITICAL',
        'mitre':       'TA0010 — Exfiltration',
        'action':      'Immediately isolate affected systems and rotate all credentials'
    },
    frozenset([1, 2, 5]): {
        'name':        'Known CVE Exploitation',
        'description': 'Vulnerable code + network attack + known CVE — attacker exploiting a specific known vulnerability',
        'severity':    'CRITICAL',
        'mitre':       'TA0002 — Execution via known exploit',
        'action':      'Patch immediately and review all traffic from source IP'
    },
    frozenset([7, 9, 6]): {
        'name':        'AI-Assisted Targeted Attack',
        'description': 'Prompt injection + anomalous behavior + credential exposure — AI-powered attack targeting your LLM pipeline',
        'severity':    'CRITICAL',
        'mitre':       'AML.T0051 — LLM Prompt Injection',
        'action':      'Block AI pipeline inputs, audit all recent LLM interactions'
    },
    frozenset([2, 7]): {
        'name':        'AI-Augmented Network Attack',
        'description': 'Network intrusion + prompt injection — attacker using AI to assist network breach',
        'severity':    'HIGH',
        'mitre':       'TA0001 + AML.T0051',
        'action':      'Enable enhanced logging on all AI endpoints'
    },
    frozenset([1, 6]): {
        'name':        'Insider Threat or Supply Chain Attack',
        'description': 'Vulnerable code + exposed secrets in same codebase — possible malicious developer or compromised dependency',
        'severity':    'HIGH',
        'mitre':       'TA0006 — Credential Access',
        'action':      'Audit recent commits and review all developers with access'
    },
    frozenset([9, 2]): {
        'name':        'Novel/Zero-Day Attack',
        'description': 'Anomalous behavior + network attack — pattern does not match known signatures, possible zero-day',
        'severity':    'HIGH',
        'mitre':       'TA0001 — Initial Access via unknown vector',
        'action':      'Capture full packet logs and escalate to security team'
    },
    frozenset([3, 6, 2]): {
        'name':        'Malware with C2 Communication',
        'description': 'Malware detected + credential exposure + network activity — active malware phoning home',
        'severity':    'CRITICAL',
        'mitre':       'TA0011 — Command and Control',
        'action':      'Immediately quarantine system and begin incident response'
    },
}

def bayesian_update(prior, layer_signals):
    """
    Update attack probability using Bayes theorem for each layer signal.
    Returns final posterior probability of attack.
    """
    p_attack = prior

    for layer_id, signal_strength in layer_signals.items():
        if layer_id not in LAYER_PRIORS:
            continue

        layer = LAYER_PRIORS[layer_id]
        p_signal_attack = layer['P_signal_given_attack'] * signal_strength
        p_signal_benign = layer['P_signal_given_benign'] * signal_strength

        # Bayes update
        numerator   = p_signal_attack * p_attack
        denominator = numerator + p_signal_benign * (1 - p_attack)

        if denominator > 0:
            p_attack = numerator / denominator

    return p_attack

def apply_correlations(base_probability, active_layers):
    """
    Boost probability when dangerous layer combinations are active.
    """
    boost = 1.0
    layer_set = set(active_layers)

    for (layer_a, layer_b), multiplier in CORRELATION_MATRIX.items():
        if layer_a in layer_set and layer_b in layer_set:
            boost *= multiplier

    # Apply boost but cap at 0.999
    import math
    dampened_boost = 1 + math.log(boost) if boost > 1 else boost
    boosted = min(0.999, base_probability * dampened_boost)
    return boosted, boost

def identify_attack_scenario(active_layers):
    """
    Match active layer combination to known attack scenarios.
    """
    layer_set = frozenset(active_layers)
    matches   = []

    for scenario_layers, scenario_info in ATTACK_SCENARIOS.items():
        if scenario_layers.issubset(layer_set):
            matches.append(scenario_info)

    return sorted(matches, key=lambda x: x['severity'])

def calculate_confidence(layer_signals, posterior):
    """
    Confidence in the assessment based on number of corroborating signals.
    """
    num_signals = len(layer_signals)
    signal_strength = sum(layer_signals.values()) / max(num_signals, 1)

    confidence = min(1.0,
        0.3 * (num_signals / len(LAYER_PRIORS)) +
        0.4 * signal_strength +
        0.3 * posterior
    )
    return confidence

# ── Layer Scanners (inline for orchestrator) ─────────────────────────────────

def quick_scan_layer1(text):
    patterns = [
        r'os\.system|shell=True|subprocess',
        r'SELECT.{0,50}FROM.{0,50}WHERE',
        r'(?i)password\s*=\s*["\'][^"\']{6,}["\']',
        r'(?i)(md5|sha1)\s*\(',
        r'innerHTML|document\.write',
    ]
    hits = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
    return min(1.0, hits * 0.25)

def quick_scan_layer5(text):
    packages = re.findall(r'^([a-zA-Z0-9_\-\.]+)\s*[=~><!]+\s*([^\s,;]+)', text, re.MULTILINE)
    if not packages:
        return 0.0
    hit_count = 0
    for name, version in packages[:5]:
        try:
            resp = requests.post(
                'https://api.osv.dev/v1/query',
                json={'package': {'name': name, 'ecosystem': 'PyPI'}, 'version': version},
                timeout=3
            )
            if resp.status_code == 200 and resp.json().get('vulns'):
                hit_count += 1
        except Exception:
            pass
    return min(1.0, hit_count * 0.3)

def quick_scan_layer6(text):
    patterns = [
        r'AKIA[0-9A-Z]{16}',
        r'ghp_[A-Za-z0-9]{36}',
        r'sk-[A-Za-z0-9]{48}',
        r'mongodb://[^:]+:[^@]+@',
        r'-----BEGIN.*PRIVATE KEY-----',
        r'sk_live_[0-9a-zA-Z]{24,}',
    ]
    hits = sum(1 for p in patterns
               if re.search(p, text)
               and not any(x in text for x in ['EXAMPLE','YOUR_','placeholder']))
    return min(1.0, hits * 0.4)

def quick_scan_layer7(text):
    patterns = [
        r'(?i)ignore.{0,20}previous.{0,20}instructions',
        r'(?i)DAN|do anything now|jailbreak',
        r'(?i)reveal.{0,20}system.{0,20}prompt',
        r'(?i)you are now|act as.{0,20}without.{0,20}restriction',
    ]
    hits = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
    return min(1.0, hits * 0.35)

def quick_scan_layer9(text):
    score = 0.0
    counter  = Counter(text)
    length   = len(text)
    entropy  = -sum((c/length)*math.log2(c/length) for c in counter.values() if c > 0) if length > 0 else 0

    if entropy > 5.0:
        score += 0.3
    if len(re.findall(r'\\x[0-9a-fA-F]{2}', text)) > 5:
        score += 0.4
    if len(re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)) > 2:
        score += 0.2
    if len(re.findall(r'\b(eval|exec|system)\b', text, re.IGNORECASE)) > 1:
        score += 0.3
    return min(1.0, score)

def quick_scan_layer10(text):
    bad_ips = ['185.220.', '194.165.', '45.142.', '91.108.']
    bad_tlds = ['.xyz', '.top', '.click', '.download', '.bit']
    score = 0.0
    for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
        if any(ip.startswith(b) for b in bad_ips):
            score += 0.5
    for domain in re.findall(r'\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})\b', text):
        if any(domain.endswith(t) for t in bad_tlds):
            score += 0.3
    return min(1.0, score)

def run_all_layers(text, include_cve=False):
    signals = {}

    s1 = quick_scan_layer1(text)
    if s1 > 0: signals[1] = s1

    if include_cve:
        s5 = quick_scan_layer5(text)
        if s5 > 0: signals[5] = s5

    s6 = quick_scan_layer6(text)
    if s6 > 0: signals[6] = s6

    s7 = quick_scan_layer7(text)
    if s7 > 0: signals[7] = s7

    s9 = quick_scan_layer9(text)
    if s9 > 0: signals[9] = s9

    s10 = quick_scan_layer10(text)
    if s10 > 0: signals[10] = s10

    return signals

def get_risk_label(probability):
    if probability >= 0.90: return ('CRITICAL', '🔴', 'Immediate action required')
    if probability >= 0.70: return ('HIGH',     '🟠', 'Urgent investigation needed')
    if probability >= 0.40: return ('MODERATE', '🟡', 'Review recommended')
    if probability >= 0.15: return ('LOW',      '🟢', 'Monitor closely')
    return                         ('SAFE',     '✅', 'No significant threat detected')

# ── Session State for History ─────────────────────────────────────────────────

if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# ── UI ────────────────────────────────────────────────────────────────────────

tab1, tab2, tab3 = st.tabs([
    "🎯 Unified Analysis",
    "📊 Correlation Matrix",
    "📜 Scan History"
])

with tab1:
    st.markdown("### Bayesian Multi-Layer Threat Analysis")
    st.info("The Orchestrator doesn't just combine scores — it uses Bayesian inference to calculate the TRUE probability of an attack based on which layers fire together.")

    input_text = st.text_area(
        "Input for analysis",
        height=280,
        placeholder="Paste any content — code, logs, network data, user input, config files..."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        analyze_btn = st.button("🧠 Run Cognitive Analysis",
                                 type="primary", use_container_width=True)
    with col2:
        include_cve = st.checkbox("Include CVE scan (slower)", value=False)
    with col3:
        show_math = st.checkbox("Show Bayesian math", value=False)

    if analyze_btn and input_text.strip():
        with st.spinner("Running Bayesian correlation across all layers..."):
            progress = st.progress(0)

            # Run all layers
            layer_signals = run_all_layers(input_text, include_cve)
            progress.progress(60)

            # Bayesian update
            posterior = bayesian_update(BASE_ATTACK_RATE, layer_signals)
            progress.progress(75)

            # Apply correlations
            correlated_prob, boost = apply_correlations(posterior, list(layer_signals.keys()))
            progress.progress(85)

            # Identify scenarios
            scenarios = identify_attack_scenario(list(layer_signals.keys()))
            progress.progress(90)

            # Confidence
            confidence = calculate_confidence(layer_signals, correlated_prob)
            progress.progress(100)
            progress.empty()

        risk_label = get_risk_label(correlated_prob)

        st.divider()

        # ── Main result ──
        st.markdown(f"## {risk_label[1]} {risk_label[0]} — Attack Probability: {correlated_prob:.1%}")
        st.markdown(f"*{risk_label[2]}*")

        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Attack Probability",  f"{correlated_prob:.1%}")
        with m2:
            st.metric("Prior Probability",   f"{BASE_ATTACK_RATE:.1%}")
        with m3:
            st.metric("Correlation Boost",   f"{boost:.1f}×")
        with m4:
            st.metric("Layers Triggered",    f"{len(layer_signals)}/{len(LAYER_PRIORS)}")
        with m5:
            st.metric("Confidence",          f"{confidence:.1%}")

        if correlated_prob >= 0.90:
            st.error(f"🚨 CRITICAL — {correlated_prob:.1%} probability of active attack. Immediate response required.")
        elif correlated_prob >= 0.70:
            st.error(f"🟠 HIGH THREAT — {correlated_prob:.1%} probability. Urgent investigation needed.")
        elif correlated_prob >= 0.40:
            st.warning(f"⚠️ MODERATE — {correlated_prob:.1%} probability. Review recommended.")
        elif correlated_prob >= 0.15:
            st.info(f"ℹ️ LOW — {correlated_prob:.1%} probability. Monitor.")
        else:
            st.success(f"✅ SAFE — {correlated_prob:.1%} probability. No significant threat.")

        # ── Attack scenarios ──
        if scenarios:
            st.divider()
            st.markdown("### 🎯 Identified Attack Scenarios")
            for scenario in scenarios:
                sev  = scenario['severity']
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MODERATE': '🟡'}.get(sev, '⚪')
                with st.expander(f"{icon} {sev} — {scenario['name']}", expanded=True):
                    st.markdown(f"**Description:** {scenario['description']}")
                    st.markdown(f"**MITRE ATT&CK:** `{scenario['mitre']}`")
                    st.error(f"**Immediate Action:** {scenario['action']}")

        # ── Layer signals ──
        if layer_signals:
            st.divider()
            st.markdown("### 📡 Layer Signal Breakdown")
            for layer_id, strength in sorted(layer_signals.items(),
                                              key=lambda x: x[1], reverse=True):
                layer_name = LAYER_PRIORS.get(layer_id, {}).get('name', f'Layer {layer_id}')
                st.progress(float(strength),
                            text=f"{layer_name}: {strength:.1%} signal strength")

        # ── Bayesian math ──
        if show_math and layer_signals:
            st.divider()
            st.markdown("### 🔢 Bayesian Calculation")
            st.markdown(f"**Prior P(attack):** {BASE_ATTACK_RATE:.1%} (base rate)")

            running_prob = BASE_ATTACK_RATE
            for layer_id, strength in layer_signals.items():
                layer = LAYER_PRIORS.get(layer_id, {})
                old_prob = running_prob
                p_sa = layer.get('P_signal_given_attack', 0.5) * strength
                p_sb = layer.get('P_signal_given_benign', 0.1) * strength
                num  = p_sa * running_prob
                den  = num + p_sb * (1 - running_prob)
                running_prob = num / den if den > 0 else running_prob

                st.markdown(
                    f"**After {layer.get('name', 'Layer')}:** "
                    f"{old_prob:.1%} → {running_prob:.1%} "
                    f"(P(signal|attack)={p_sa:.2f}, P(signal|benign)={p_sb:.2f})"
                )

            st.markdown(f"**After correlation boost ({boost:.1f}×):** {correlated_prob:.1%}")

        # ── Active correlations ──
        if len(layer_signals) > 1:
            active_layer_set = set(layer_signals.keys())
            active_correlations = []
            for (la, lb), multiplier in CORRELATION_MATRIX.items():
                if la in active_layer_set and lb in active_layer_set:
                    name_a = LAYER_PRIORS.get(la, {}).get('name', f'L{la}')
                    name_b = LAYER_PRIORS.get(lb, {}).get('name', f'L{lb}')
                    active_correlations.append((name_a, name_b, multiplier))

            if active_correlations:
                st.divider()
                st.markdown("### ⚡ Active Correlations")
                for name_a, name_b, mult in sorted(active_correlations,
                                                    key=lambda x: x[2], reverse=True):
                    st.markdown(f"🔗 **{name_a}** + **{name_b}** → `{mult}×` threat multiplier")

        # ── Save to history ──
        st.session_state.scan_history.append({
            'time':        datetime.now().strftime('%H:%M:%S'),
            'probability': correlated_prob,
            'risk':        risk_label[0],
            'layers':      list(layer_signals.keys()),
            'scenarios':   [s['name'] for s in scenarios],
            'input':       input_text[:100] + '...' if len(input_text) > 100 else input_text
        })

        # ── Download ──
        st.divider()
        report = {
            'timestamp':         datetime.now().isoformat(),
            'attack_probability': correlated_prob,
            'risk_level':        risk_label[0],
            'confidence':        confidence,
            'correlation_boost': boost,
            'layer_signals':     layer_signals,
            'scenarios':         scenarios,
            'bayesian_prior':    BASE_ATTACK_RATE,
        }
        st.download_button(
            "📥 Download Orchestrator Report",
            json.dumps(report, indent=2),
            file_name=f"guardai_orchestrator_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )

    elif analyze_btn:
        st.warning("Paste content to analyze.")

with tab2:
    st.markdown("### Layer Correlation Matrix")
    st.markdown("How dangerous each layer combination is when they fire together:")

    st.markdown("#### High-Danger Combinations")
    sorted_correlations = sorted(CORRELATION_MATRIX.items(),
                                  key=lambda x: x[1], reverse=True)
    for (la, lb), multiplier in sorted_correlations:
        name_a = LAYER_PRIORS.get(la, {}).get('name', f'Layer {la}')
        name_b = LAYER_PRIORS.get(lb, {}).get('name', f'Layer {lb}')
        bar_width = int((multiplier / 5.0) * 100)
        danger = '🔴' if multiplier >= 4.0 else '🟠' if multiplier >= 3.0 else '🟡'
        st.markdown(f"{danger} **{name_a}** + **{name_b}**: `{multiplier}×` multiplier")
        st.progress(min(1.0, multiplier / 5.0))

    st.divider()
    st.markdown("#### Attack Scenarios")
    for scenario_layers, info in ATTACK_SCENARIOS.items():
        sev  = info['severity']
        icon = {'CRITICAL': '🔴', 'HIGH': '🟠'}.get(sev, '🟡')
        layer_names = [LAYER_PRIORS.get(l, {}).get('name', f'L{l}') for l in scenario_layers]
        with st.expander(f"{icon} {info['name']}"):
            st.markdown(f"**Triggered by:** {' + '.join(layer_names)}")
            st.markdown(f"**Description:** {info['description']}")
            st.markdown(f"**MITRE:** `{info['mitre']}`")

with tab3:
    st.markdown("### Scan History")
    if not st.session_state.scan_history:
        st.info("No scans yet. Run an analysis to see history here.")
    else:
        for i, scan in enumerate(reversed(st.session_state.scan_history)):
            risk  = scan['risk']
            icon  = {'CRITICAL':'🔴','HIGH':'🟠','MODERATE':'🟡','LOW':'🟢','SAFE':'✅'}.get(risk,'⚪')
            with st.expander(
                f"{icon} {scan['time']} — {risk} ({scan['probability']:.1%})",
                expanded=(i == 0)
            ):
                st.markdown(f"**Risk:** {risk}")
                st.markdown(f"**Probability:** {scan['probability']:.1%}")
                st.markdown(f"**Layers triggered:** {scan['layers']}")
                if scan['scenarios']:
                    st.markdown(f"**Scenarios:** {', '.join(scan['scenarios'])}")
                st.caption(f"Input: {scan['input']}")

        if st.button("Clear History"):
            st.session_state.scan_history = []
            st.rerun()

st.divider()
st.caption("GuardAI Layer 31 | Cognitive Security Orchestrator | Bayesian signal correlation | MITRE ATT&CK mapped")
