import streamlit as st
import torch
import subprocess
import json
import tempfile
import os
import zipfile
import io
from transformers import AutoTokenizer, RobertaForSequenceClassification
from fpdf import FPDF
from datetime import datetime
import numpy as np

# ── Page config ───────────────────────────────────────────
st.set_page_config(
    page_title="GuardAI",
    page_icon="shield",
    layout="wide"
)

# ── OWASP Top 10 mapping ──────────────────────────────────
OWASP_MAP = {
    # ── Bandit (Python) ──────────────────────────────────
    'B608': ('A03', 'Injection',                'Use parameterized queries instead of string concatenation'),
    'B605': ('A03', 'Injection',                'Use subprocess.run() with shell=False and a list of arguments'),
    'B602': ('A03', 'Injection',                'Avoid shell=True in subprocess calls'),
    'B603': ('A03', 'Injection',                'Avoid subprocess with untrusted input'),
    'B604': ('A03', 'Injection',                'Avoid function calls with shell=True'),
    'B606': ('A03', 'Injection',                'Avoid os.system() - use subprocess with shell=False'),
    'B607': ('A03', 'Injection',                'Avoid starting processes with partial paths'),
    'B301': ('A08', 'Insecure Deserialization', 'Use json.loads() instead of pickle.loads()'),
    'B302': ('A08', 'Insecure Deserialization', 'Avoid marshal.loads() - use json instead'),
    'B403': ('A08', 'Insecure Deserialization', 'Avoid importing pickle - use JSON for serialization'),
    'B404': ('A03', 'Injection',                'Review use of subprocess - ensure input is sanitized'),
    'B105': ('A07', 'Identification Failures',  'Store credentials in environment variables, not in code'),
    'B106': ('A07', 'Identification Failures',  'Never hardcode passwords in source code'),
    'B107': ('A07', 'Identification Failures',  'Use environment variables for all secrets'),
    'B101': ('A05', 'Security Misconfiguration','Remove assert statements from production code'),
    'B110': ('A05', 'Security Misconfiguration','Do not use bare except - catch specific exceptions'),
    'B112': ('A05', 'Security Misconfiguration','Do not use continue in bare except blocks'),
    'B201': ('A05', 'Security Misconfiguration','Disable Flask debug mode in production'),
    'B703': ('A03', 'Injection',                'Use Django ORM or parameterized queries'),
    'B308': ('A03', 'Injection',                'Avoid mark_safe() with user-controlled input'),
    'B324': ('A02', 'Cryptographic Failures',   'Use SHA-256 or higher instead of MD5/SHA1'),
    'B303': ('A02', 'Cryptographic Failures',   'Use bcrypt for password hashing'),
    'B304': ('A02', 'Cryptographic Failures',   'Use AES-256 instead of DES/3DES/RC4/Blowfish'),
    'B305': ('A02', 'Cryptographic Failures',   'Avoid deprecated cipher modes like ECB'),
    'B311': ('A02', 'Cryptographic Failures',   'Use secrets module instead of random for security tokens'),
    'B501': ('A02', 'Cryptographic Failures',   'Enable SSL/TLS certificate verification'),
    'B502': ('A02', 'Cryptographic Failures',   'Do not disable SSL verification'),
    'B503': ('A02', 'Cryptographic Failures',   'Avoid SSLv2/SSLv3 - use TLS 1.2+'),
    'B504': ('A02', 'Cryptographic Failures',   'Set minimum TLS version to 1.2'),
    'B505': ('A02', 'Cryptographic Failures',   'Use RSA key size >= 2048 bits'),
    'B601': ('A03', 'Injection',                'Avoid paramiko exec_command with user input'),
    'B611': ('A03', 'Injection',                'Avoid raw SQL queries with user input in Django'),
    'B506': ('A08', 'Insecure Deserialization', 'Use yaml.safe_load() instead of yaml.load()'),
    'B108': ('A05', 'Security Misconfiguration','Avoid predictable temp file paths'),
    'B320': ('A03', 'Injection',                'Use defusedxml instead of lxml for untrusted XML'),
    'B410': ('A03', 'Injection',                'Avoid using lxml - use defusedxml instead'),
    'B411': ('A03', 'Injection',                'Avoid xmlrpc - vulnerable to XXE and SSRF'),
    'B412': ('A03', 'Injection',                'Avoid httpoxy - use direct HTTP client libraries'),
    'B413': ('A02', 'Cryptographic Failures',   'Avoid pycrypto - use cryptography library instead'),
    'B701': ('A03', 'Injection',                'Use Jinja2 autoescape=True to prevent XSS'),
    'B702': ('A03', 'Injection',                'Use Mako defenses.escape() for template output'),

    # ── Semgrep JavaScript / TypeScript ──────────────────
    'javascript.lang.security.audit.eval.js-eval':
        ('A03', 'Injection', 'Never use eval() with user input - use JSON.parse() instead'),
    'javascript.lang.security.audit.eval.js-implied-eval':
        ('A03', 'Injection', 'Avoid setTimeout/setInterval with string arguments'),
    'javascript.lang.security.audit.sqli.node-mysql-sqli':
        ('A03', 'Injection', 'Use parameterized queries with node-mysql'),
    'javascript.lang.security.audit.sqli.node-postgres-sqli':
        ('A03', 'Injection', 'Use parameterized queries - pass values array to pg.query()'),
    'javascript.lang.security.audit.xss.react.dangerously-set-inner-html':
        ('A03', 'XSS', 'Avoid dangerouslySetInnerHTML - use textContent or sanitize with DOMPurify'),
    'javascript.lang.security.audit.xss.no-document-write':
        ('A03', 'XSS', 'Avoid document.write() - use DOM manipulation methods instead'),
    'javascript.lang.security.audit.xss.no-inner-html':
        ('A03', 'XSS', 'Avoid innerHTML - use textContent or sanitize input first'),
    'javascript.lang.security.audit.path-traversal.path-join-resolve-traversal':
        ('A01', 'Broken Access Control', 'Validate and normalize file paths before use'),
    'javascript.lang.security.audit.command-injection.child-process-injection':
        ('A03', 'Injection', 'Never pass user input to exec() - use execFile() with argument array'),
    'javascript.lang.security.detect-non-literal-regexp':
        ('A03', 'Injection', 'Avoid building RegExp from user input - ReDoS risk'),
    'javascript.lang.security.audit.prototype-pollution':
        ('A08', 'Software Integrity Failures', 'Validate object keys - avoid setting __proto__ properties'),
    'javascript.express.security.audit.express-cookie-settings':
        ('A05', 'Security Misconfiguration', 'Set httpOnly and secure flags on Express session cookies'),
    'javascript.jwt.security.audit.jwt-hardcoded-secret':
        ('A07', 'Identification Failures', 'Never hardcode JWT secrets - load from environment variables'),
    'javascript.lang.security.audit.hardcoded-secret':
        ('A07', 'Identification Failures', 'Move hardcoded secrets to environment variables'),
    'javascript.lang.security.audit.ssrf.axios-ssrf':
        ('A10', 'SSRF', 'Validate and whitelist URLs before making HTTP requests'),
    'javascript.lang.security.audit.ssrf.node-fetch-ssrf':
        ('A10', 'SSRF', 'Never use user-controlled URLs in server-side fetch calls'),
    'javascript.lang.security.detect-child-process':
        ('A03', 'Injection', 'Avoid child_process.exec with user input'),

    # ── Semgrep PHP ───────────────────────────────────────
    'php.lang.security.injection.sql-injection':
        ('A03', 'Injection', 'Use PDO prepared statements instead of string concatenation'),
    'php.lang.security.xss.echo-unescaped':
        ('A03', 'XSS', 'Use htmlspecialchars() before echoing user input'),
    'php.lang.security.injection.command-injection':
        ('A03', 'Injection', 'Avoid exec()/system() with user input - use escapeshellarg()'),
    'php.lang.security.deserialization.unserialize-user-input':
        ('A08', 'Insecure Deserialization', 'Never unserialize() user-controlled data'),
    'php.lang.security.audit.path-traversal':
        ('A01', 'Broken Access Control', 'Validate file paths with realpath() and check prefix'),
    'php.lang.security.crypto.weak-hash':
        ('A02', 'Cryptographic Failures', 'Use password_hash() with PASSWORD_BCRYPT instead of md5/sha1'),
    'php.lang.security.audit.hardcoded-credentials':
        ('A07', 'Identification Failures', 'Store credentials in environment variables or vault'),
    'php.lang.security.audit.xxe.simplexml-xxe':
        ('A05', 'Security Misconfiguration', 'Disable external entity loading with LIBXML_NOENT'),

    # ── Semgrep Java ──────────────────────────────────────
    'java.lang.security.audit.sqli.jdbc-sqli':
        ('A03', 'Injection', 'Use PreparedStatement with parameterized queries'),
    'java.lang.security.audit.sqli.spring-sqli':
        ('A03', 'Injection', 'Use Spring JdbcTemplate with ? placeholders'),
    'java.lang.security.audit.xss.xss-in-servlet':
        ('A03', 'XSS', 'Encode output with OWASP Java Encoder before writing to response'),
    'java.lang.security.audit.command-injection.runtime-exec':
        ('A03', 'Injection', 'Avoid Runtime.exec() with user input - use ProcessBuilder with array args'),
    'java.lang.security.audit.crypto.use-of-md5':
        ('A02', 'Cryptographic Failures', 'Use SHA-256 or higher - MD5 is broken'),
    'java.lang.security.audit.crypto.use-of-sha1':
        ('A02', 'Cryptographic Failures', 'Use SHA-256 or higher - SHA1 is deprecated'),
    'java.lang.security.audit.crypto.weak-random':
        ('A02', 'Cryptographic Failures', 'Use SecureRandom instead of java.util.Random for security'),
    'java.lang.security.audit.deserialization.object-deserialization':
        ('A08', 'Insecure Deserialization', 'Avoid Java native deserialization - use JSON/protobuf'),
    'java.lang.security.audit.path-traversal.path-traversal-in':
        ('A01', 'Broken Access Control', 'Normalize paths with Paths.get().normalize() and validate prefix'),
    'java.lang.security.audit.xxe.documentbuilderfactory-xxe':
        ('A05', 'Security Misconfiguration', 'Disable DOCTYPE declarations in DocumentBuilderFactory'),
    'java.lang.security.audit.hardcoded-password-field':
        ('A07', 'Identification Failures', 'Load credentials from environment or secrets manager'),
    'java.spring.security.injection.tainted-sql-string':
        ('A03', 'Injection', 'Use Spring Data JPA or parameterized queries'),

    # ── Semgrep Go ────────────────────────────────────────
    'go.lang.security.audit.sqli.pg-sqli':
        ('A03', 'Injection', 'Use $1 placeholders with db.Query() - never concatenate SQL'),
    'go.lang.security.audit.sqli.mysql-sqli':
        ('A03', 'Injection', 'Use ? placeholders with database/sql prepared statements'),
    'go.lang.security.audit.xss.template-unescaped':
        ('A03', 'XSS', 'Use html/template instead of text/template for HTML output'),
    'go.lang.security.audit.crypto.use-of-md5':
        ('A02', 'Cryptographic Failures', 'Replace crypto/md5 with crypto/sha256'),
    'go.lang.security.audit.crypto.use-of-sha1':
        ('A02', 'Cryptographic Failures', 'Replace crypto/sha1 with crypto/sha256'),
    'go.lang.security.audit.crypto.weak-random':
        ('A02', 'Cryptographic Failures', 'Use crypto/rand instead of math/rand for security tokens'),
    'go.lang.security.audit.path-traversal.path-traversal':
        ('A01', 'Broken Access Control', 'Use filepath.Clean() and verify path stays within allowed dir'),
    'go.lang.security.audit.ssrf.http-request-tainted':
        ('A10', 'SSRF', 'Validate and whitelist URLs before making outbound requests'),
    'go.lang.security.audit.hardcoded-credentials':
        ('A07', 'Identification Failures', 'Use os.Getenv() or a secrets manager'),

    # ── Semgrep C / C++ ──────────────────────────────────
    'c.lang.security.buffer-overflow.strcpy':
        ('A03', 'Injection', 'Replace strcpy() with strncpy() or strlcpy() with size limit'),
    'c.lang.security.buffer-overflow.gets':
        ('A03', 'Injection', 'Replace gets() with fgets() - gets() has no bounds checking'),
    'c.lang.security.buffer-overflow.sprintf':
        ('A03', 'Injection', 'Replace sprintf() with snprintf() with explicit buffer size'),
    'c.lang.security.injection.command-injection':
        ('A03', 'Injection', 'Avoid system() with user input - use execve() with argument array'),
    'c.lang.security.format-string.printf-format-string':
        ('A03', 'Injection', 'Never pass user input as printf format string - use printf("%s", input)'),
    'c.lang.security.memory.use-after-free':
        ('A06', 'Vulnerable Components', 'Set pointer to NULL immediately after free()'),
    'c.lang.security.memory.double-free':
        ('A06', 'Vulnerable Components', 'Track ownership carefully - never free() the same pointer twice'),

    # ── Semgrep C# ───────────────────────────────────────
    'csharp.lang.security.sqli.csharp-sqli':
        ('A03', 'Injection', 'Use SqlCommand with SqlParameter - never concatenate SQL strings'),
    'csharp.lang.security.audit.xss.no-direct-response-write':
        ('A03', 'XSS', 'Encode output with HttpUtility.HtmlEncode() before Response.Write()'),
    'csharp.lang.security.audit.crypto.use-of-md5':
        ('A02', 'Cryptographic Failures', 'Replace MD5 with SHA256Managed or SHA512Managed'),
    'csharp.lang.security.audit.crypto.use-of-sha1':
        ('A02', 'Cryptographic Failures', 'Replace SHA1 with SHA256Managed or higher'),
    'csharp.lang.security.audit.crypto.weak-random':
        ('A02', 'Cryptographic Failures', 'Use RNGCryptoServiceProvider instead of System.Random'),
    'csharp.lang.security.audit.path-traversal':
        ('A01', 'Broken Access Control', 'Use Path.GetFullPath() and verify it starts with allowed base path'),
    'csharp.lang.security.audit.xxe.xmldocument-xxe':
        ('A05', 'Security Misconfiguration', 'Set XmlResolver = null and DtdProcessing = Prohibit'),
    'csharp.lang.security.audit.hardcoded-credentials':
        ('A07', 'Identification Failures', 'Use ConfigurationManager or Azure Key Vault for secrets'),
    'csharp.lang.security.deserialization.binaryformatter':
        ('A08', 'Insecure Deserialization', 'BinaryFormatter is deprecated - use System.Text.Json instead'),
    'csharp.lang.security.audit.command-injection':
        ('A03', 'Injection', 'Never pass user input to Process.Start() arguments'),

    # ── Semgrep Ruby ─────────────────────────────────────
    'ruby.lang.security.audit.sqli.activerecord-sqli':
        ('A03', 'Injection', 'Use ActiveRecord query methods with hash conditions, not string interpolation'),
    'ruby.lang.security.audit.xss.xss-in-controller':
        ('A03', 'XSS', 'Use html_escape() or h() helper before rendering user input'),
    'ruby.lang.security.audit.crypto.use-of-md5':
        ('A02', 'Cryptographic Failures', 'Use BCrypt or Argon2 for passwords, SHA-256 for hashing'),
    'ruby.lang.security.audit.command-injection':
        ('A03', 'Injection', 'Use system() with array args or avoid shell=true equivalent'),
    'ruby.lang.security.audit.deserialization.marshal-load':
        ('A08', 'Insecure Deserialization', 'Avoid Marshal.load with user data - use JSON instead'),
    'ruby.lang.security.audit.hardcoded-credentials':
        ('A07', 'Identification Failures', 'Use Rails credentials or ENV variables for secrets'),
}

def get_owasp(test_id):
    return OWASP_MAP.get(
        test_id,
        ('A00', 'Unknown', 'Review this code manually with a security expert')
    )
# ADD this function after get_owasp() — around line 50
def detect_language(code):
    """
    Automatically detects programming language from code patterns.
    Returns language name as string.
    """
    code_lower = code.lower()

    # Strong indicators first
    if any(x in code for x in ['<?php', 'echo $_', '$_GET', '$_POST']):
        return 'PHP'

    if any(x in code for x in ['import java.', 'public class ', 'System.out.println']):
        return 'Java'

    if any(x in code for x in ['using System;', 'namespace ', 'Console.WriteLine', '.cs']):
        return 'C#'

    if any(x in code for x in ['func ', 'package main', 'import "fmt"', ':= ']):
        return 'Go'

    if any(x in code for x in ['def ', 'import os', 'print(', '__init__', 'self.']):
        return 'Python'

    if any(x in code for x in ['require ', 'module.exports', 'const ', 'let ', 'var ', '=>', 'console.log']):
        return 'JavaScript'

    if any(x in code for x in ['#include', 'int main(', 'printf(', 'malloc(']):
        if 'class ' in code and '::' in code:
            return 'C++'
        return 'C'

    if any(x in code for x in ['def ', 'require ', 'puts ', '.rb']):
        return 'Ruby'

    # Count keyword frequency as fallback
    scores = {
        'Python':     code.count('def ') + code.count('import ') + code.count('self.'),
        'JavaScript': code.count('function') + code.count('const ') + code.count('var '),
        'Java':       code.count('public ') + code.count('private ') + code.count('void '),
        'PHP':        code.count('$') + code.count('echo '),
        'Go':         code.count('func ') + code.count(':='),
        'C':          code.count('#include') + code.count('printf'),
        'C++':        code.count('cout') + code.count('::'),
        'C#':         code.count('using ') + code.count('Console.'),
    }
    detected = max(scores, key=scores.get)
    return detected if scores[detected] > 0 else 'Python'
# ── Load AI model ─────────────────────────────────────────
@st.cache_resource
def load_model():
    path = "models/guardai-model-final"
    if not os.path.exists(path):
        return None, None
    try:
        tokenizer = AutoTokenizer.from_pretrained(path)
        model = RobertaForSequenceClassification.from_pretrained(path)
        model.eval()
        return tokenizer, model
    except Exception:
        return None, None

# ── AI prediction ─────────────────────────────────────────
def predict(code, tokenizer, model):
    inputs = tokenizer(
        code,
        max_length=256,
        truncation=True,
        padding='max_length',
        return_tensors='pt'
    )
    with torch.no_grad():
        outputs = model(**inputs)
    probs      = torch.softmax(outputs.logits, dim=1)[0]
    label      = torch.argmax(probs).item()
    confidence = probs[label].item()
    vuln_prob  = probs[1].item()
    return label, confidence, vuln_prob

# ── Bandit static scan (Python) ───────────────────────────
def run_bandit(code):
    with tempfile.NamedTemporaryFile(
        suffix='.py', mode='w', delete=False
    ) as f:
        f.write(code)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ['bandit', tmp_path, '-f', 'json', '-l', '-i', '--silent'],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            return data.get('results', [])
        return []
    except Exception:
        return []
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

# ── Semgrep scan (JavaScript, PHP, Java, Go, Ruby, C, C++) ─
def run_semgrep(code, language):
    ext_map = {
    'JavaScript': '.js',
    'PHP':        '.php',
    'Java':       '.java',
    'Go':         '.go',
    'Ruby':       '.rb',
    'C':          '.c',
    'C++':        '.cpp',
    'C#':         '.cs',
}
    ext = ext_map.get(language, '.txt')

    with tempfile.NamedTemporaryFile(
        suffix=ext, mode='w', delete=False
    ) as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ['semgrep', '--config=auto', '--json', '--quiet', tmp_path],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout.strip():
            data     = json.loads(result.stdout)
            findings = []
            for r in data.get('results', []):
                findings.append({
                    'test_id':        r.get('check_id', ''),
                    'issue_severity': _map_semgrep_severity(
                        r.get('extra', {}).get('severity', 'INFO')
                    ),
                    'issue_text':     r.get('extra', {}).get('message', ''),
                    'line_number':    r.get('start', {}).get('line', 0),
                })
            return findings
        return []
    except Exception:
        return []
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

def _map_semgrep_severity(severity):
    return {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}.get(
        severity.upper(), 'LOW'
    )

# ── ESLint scan (JavaScript extra rules) ──────────────────
def run_eslint(code):
    with tempfile.NamedTemporaryFile(
        suffix='.js', mode='w', delete=False
    ) as f:
        f.write(code)
        tmp_path = f.name
    try:
        result = subprocess.run(
            [
                'eslint', tmp_path,
                '--format=json',
                '--no-eslintrc',
                '--rule', '{"no-eval":"error","no-implied-eval":"error"}'
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            data     = json.loads(result.stdout)
            findings = []
            for file_result in data:
                for msg in file_result.get('messages', []):
                    findings.append({
                        'test_id':        msg.get('ruleId', ''),
                        'issue_severity': 'HIGH' if msg.get('severity') == 2 else 'MEDIUM',
                        'issue_text':     msg.get('message', ''),
                        'line_number':    msg.get('line', 0),
                    })
            return findings
        return []
    except Exception:
        return []
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

# ── Route scanner by language ─────────────────────────────
def scan_code(code, language):
    if language == 'Python':
        return run_bandit(code)
    elif language == 'JavaScript':
        results = run_semgrep(code, language)
        results.extend(run_eslint(code))
        return results
    else:
        return run_semgrep(code, language)

# ── Smart verdict logic ───────────────────────────────────
def get_verdict(vuln_prob, bandit_results, language):
    high_count   = sum(1 for r in bandit_results if r.get('issue_severity') == 'HIGH')
    medium_count = sum(1 for r in bandit_results if r.get('issue_severity') == 'MEDIUM')
    low_count    = sum(1 for r in bandit_results if r.get('issue_severity') == 'LOW')
    bandit_count = len(bandit_results)

    if vuln_prob > 0.85 and high_count > 0:
        return 'CRITICAL', 'red',    'CRITICAL'
    if vuln_prob > 0.60 and bandit_count > 0:
        return 'HIGH',     'orange', 'HIGH'
    if high_count > 0:
        return 'HIGH',     'orange', 'HIGH'
    if medium_count > 0:
        return 'MEDIUM',   'yellow', 'MEDIUM'
    if low_count > 0:
        return 'LOW',      'blue',   'LOW'
    if vuln_prob > 0.55:
        return 'REVIEW',   'blue',   'REVIEW'
    return     'SAFE',     'green',  'SAFE'

# ── Highlight vulnerable lines ────────────────────────────
def highlight_code_lines(code, bandit_results):
    if not bandit_results:
        return
    vulnerable_lines = {}
    for issue in bandit_results:
        ln  = issue.get('line_number', 0)
        sev = issue.get('issue_severity', '')
        txt = issue.get('issue_text', '')
        vulnerable_lines[ln] = (sev, txt)

    st.markdown("**Exact location of issues:**")
    lines     = code.split('\n')
    annotated = []
    for i, line in enumerate(lines, 1):
        if i in vulnerable_lines:
            sev, _ = vulnerable_lines[i]
            if sev == 'HIGH':
                annotated.append(f"[HIGH]   Line {i:3d} | {line}  <- HIGH RISK")
            elif sev == 'MEDIUM':
                annotated.append(f"[MEDIUM] Line {i:3d} | {line}  <- MEDIUM RISK")
            else:
                annotated.append(f"[LOW]    Line {i:3d} | {line}  <- LOW RISK")
        else:
            annotated.append(f"         Line {i:3d} | {line}")
    st.code('\n'.join(annotated), language='text')

    st.markdown("**Vulnerable lines summary:**")
    for ln, (sev, txt) in sorted(vulnerable_lines.items()):
        st.markdown(f"- **Line {ln}** `{sev}` - {txt}")

# ── Fix suggestions ───────────────────────────────────────
SEVERITY_FIXES = {
    'CRITICAL': [
        'Stop using this code in production immediately',
        'Apply the fix shown in findings before any deployment',
        'Run a full security audit of all related code',
        'Notify your security team',
    ],
    'HIGH': [
        'Fix this issue before the next deployment',
        'Add input validation and output encoding',
        'Review all similar patterns in your codebase',
    ],
    'MEDIUM': [
        'Schedule a fix in the next sprint',
        'Add unit tests that verify secure behavior',
        'Consider a focused code review on this area',
    ],
    'LOW': [
        'Low risk - fix when convenient',
        'Add to your technical debt backlog',
    ],
    'REVIEW': [
        'AI flagged this but static analysis found nothing',
        'Review manually - may be a false positive',
        'If this code handles network user input, add validation',
    ],
    'SAFE': [
        'No issues found - code appears secure',
        'Continue following secure coding practices',
        'Consider adding security unit tests',
    ],
}

# ── PDF report generator ──────────────────────────────────
def generate_pdf(code, language, verdict, vuln_prob, bandit_results):
    pdf = FPDF()
    pdf.add_page()

    # Header
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 15, 'GuardAI Security Report', fill=True, ln=True, align='C')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Metadata
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 7, f'Date         : {datetime.now().strftime("%Y-%m-%d %H:%M")}', ln=True)
    pdf.cell(0, 7, f'Language     : {language}', ln=True)
    pdf.cell(0, 7, f'AI Vuln Prob : {vuln_prob*100:.1f}%', ln=True)
    pdf.cell(0, 7, f'Total Issues : {len(bandit_results)}', ln=True)
    pdf.ln(4)

    # Verdict box
    pdf.set_font('Helvetica', 'B', 14)
    colors = {
        'CRITICAL': (220, 38,  38),
        'HIGH':     (234, 88,  12),
        'MEDIUM':   (202, 138,  4),
        'LOW':      (37,  99, 235),
        'REVIEW':   (37,  99, 235),
        'SAFE':     (22, 163,  74),
    }
    r, g, b = colors.get(verdict, (22, 163, 74))
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 12, f'Overall Risk: {verdict}', fill=True, ln=True, align='C')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Findings
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 9, f'Static Analysis Findings ({len(bandit_results)} issues found)', ln=True)
    pdf.set_font('Helvetica', '', 10)

    if bandit_results:
        for issue in bandit_results:
            severity = issue.get('issue_severity', '')
            text     = issue.get('issue_text', '')
            line     = issue.get('line_number', '')
            test_id  = issue.get('test_id', '')
            _, owasp_name, fix = get_owasp(test_id)

            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 7, f'[{severity}] Line {line} - {test_id}', ln=True)
            pdf.set_font('Helvetica', '', 10)
            pdf.multi_cell(190, 6, f'Issue  : {text[:120]}')
            pdf.multi_cell(190, 6, f'OWASP  : {owasp_name[:120]}')
            pdf.multi_cell(190, 6, f'Fix    : {fix[:120]}')
            pdf.ln(3)
    else:
        pdf.cell(0, 7, 'No static analysis issues found.', ln=True)

    # Recommended actions
    pdf.ln(3)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 9, 'Recommended Actions', ln=True)
    pdf.set_font('Helvetica', '', 10)
    for action in SEVERITY_FIXES.get(verdict, []):
        pdf.multi_cell(190, 6, f'- {action[:150]}')
    pdf.ln(3)

    # Code listing
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 9, 'Scanned Code', ln=True)
    pdf.set_font('Courier', '', 7)
    pdf.set_fill_color(245, 245, 245)

    vuln_lines = {r.get('line_number', 0) for r in bandit_results}
    for i, line in enumerate(code.split('\n'), 1):
        clean   = line.replace('\t', '    ')
        marker  = ' <- ISSUE' if i in vuln_lines else ''
        snippet = f'{i:3d} | {clean[:90]}{marker}'
        try:
            pdf.cell(0, 4, snippet, fill=True, ln=True)
        except Exception:
            pdf.cell(0, 4, f'{i:3d} | [line skipped]', fill=True, ln=True)

    # Footer
    pdf.set_font('Helvetica', 'I', 8)
    pdf.ln(5)
    pdf.cell(
        0, 7,
        'GuardAI - Open source defensive security tool | For authorized assessments only',
        ln=True, align='C'
    )

    tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
    pdf.output(tmp.name)
    return tmp.name

# ─────────────────────────────────────────────────────────
# MAIN UI
# ─────────────────────────────────────────────────────────
st.title("GuardAI - Vulnerability Scanner")
st.caption(
    "AI-powered defensive security scanning | "
    "UniXcoder + VulGate | "
    "For authorized use only"
)

# Sidebar
with st.sidebar:
    st.header("About GuardAI")
    st.markdown("""
**Languages supported:**
- Python (Bandit + AI)
- JavaScript (Semgrep + ESLint + AI)
- PHP (Semgrep + AI)
- Java (Semgrep + AI)
- Go (Semgrep + AI)
- Ruby (Semgrep + AI)
- C / C++ (Semgrep + AI)

**What it detects:**
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- XSS (CWE-79)
- Insecure Deserialization (CWE-502)
- Hardcoded Credentials (CWE-798)
- Path Traversal (CWE-22)
- Weak Cryptography (CWE-327)
- 180+ more CWE types

**Model stats:**
- Dataset: VulGate (184k samples)
- Accuracy: 83.49%
    """)
    st.markdown("---")
    st.warning(
        "Only scan code you own or have "
        "written authorization to test."
    )

# Tabs
tab1, tab2 = st.tabs(["Single File Scan", "Project Scan"])

# ─────────────────────────────────────────────────────────
# TAB 1 - Single File Scan
# ─────────────────────────────────────────────────────────
with tab1:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("Code Input")
        code = st.text_area(
            "Paste your code here",
            height=420,
            placeholder=(
                "Paste any function or code block here...\n\n"
                "Supports: Python, JavaScript, PHP, Java, Go, Ruby, C, C++"
            )
        )
        language = st.selectbox(
            "Programming Language",
            ["Auto Detect", "Python", "JavaScript", "PHP", "Java", "Go", "Ruby", "C", "C++", "C#"]
        )
        scan_btn = st.button(
            "Scan for Vulnerabilities",
            type="primary",
            use_container_width=True,
            key="single_scan"
        )

    with col2:
        st.subheader("Scan Results")

        if scan_btn and code.strip():
            with st.spinner("Scanning..."):
                # Auto detect language if selected
                actual_language = language
                if language == "Auto Detect":
                    actual_language = detect_language(code)
                    st.info(f"Language detected: **{actual_language}**")
                # Load model
                tokenizer, ai_model = load_model()
                if tokenizer and ai_model:
                    label, confidence, vuln_prob = predict(
                        code, tokenizer, ai_model
                    )
                    ai_available = True
                else:
                    ai_available = False
                    label, confidence, vuln_prob = 0, 0.5, 0.0

                # Static scan - routes to correct tool per language
                static_results = scan_code(code, actual_language)

                # Smart verdict
                verdict, color, icon = get_verdict(vuln_prob, static_results, actual_language)

            # AI result
            if ai_available:
                st.markdown("**AI Model Analysis**")
                m1, m2 = st.columns(2)
                with m1:
                    st.metric("Vulnerability Probability", f"{vuln_prob*100:.1f}%")
                with m2:
                    st.metric("Model Confidence", f"{confidence*100:.1f}%")
                st.progress(float(vuln_prob))
            else:
                st.info(
                    "AI model not loaded. "
                    "Place model in models/guardai-model-final/"
                )

            # Combined verdict
            st.markdown("---")
            st.markdown("**Combined Verdict**")
            if verdict == 'CRITICAL':
                st.error(f"CRITICAL - AI and static analysis both confirm. Do not deploy.")
            elif verdict == 'HIGH':
                st.error(f"HIGH - Significant security issue. Fix before deployment.")
            elif verdict == 'MEDIUM':
                st.warning(f"MEDIUM - Potential security issue. Schedule a fix.")
            elif verdict == 'LOW':
                st.info(f"LOW - Minor issue detected. Fix when convenient.")
            elif verdict == 'REVIEW':
                st.info(f"MANUAL REVIEW - AI flagged but static analysis found nothing.")
            else:
                st.success(f"SAFE - No security issues detected.")

            # Recommended actions
            st.markdown("**Recommended Actions**")
            for fix in SEVERITY_FIXES.get(verdict, []):
                st.markdown(f"- {fix}")

            # Static findings
            if static_results:
                st.markdown("---")
                st.markdown(
                    f"**Static Analysis Findings "
                    f"({len(static_results)} issue(s) found)**"
                )
                for issue in static_results:
                    test_id  = issue.get('test_id', '')
                    severity = issue.get('issue_severity', '')
                    text     = issue.get('issue_text', '')
                    line     = issue.get('line_number', '')
                    owasp_id, owasp_name, fix = get_owasp(test_id)

                    with st.expander(
                        f"{severity} - Line {line}: {text[:55]}...",
                        expanded=(severity in ['HIGH', 'CRITICAL'])
                    ):
                        c1, c2 = st.columns(2)
                        with c1:
                            st.markdown(f"**Severity :** {severity}")
                            st.markdown(f"**Line     :** {line}")
                            st.markdown(f"**Rule     :** {test_id}")
                        with c2:
                            st.markdown(f"**OWASP    :** {owasp_id}")
                            st.markdown(f"**Category :** {owasp_name}")
                        st.markdown(f"**Issue :** {text}")
                        st.success(f"**Fix   :** {fix}")

                # Line pinpointing
                st.markdown("---")
                highlight_code_lines(code, static_results)

            elif language == "Python":
                st.success("Bandit: No static analysis issues found")
            else:
                st.info(
                    f"Semgrep scanned {language} code. "
                    f"AI result shown above."
                )

            # Summary
            st.markdown("---")
            st.markdown("**Scan Summary**")
            s1, s2, s3, s4 = st.columns(4)
            with s1:
                st.metric("AI Verdict", "VULN" if label == 1 else "SAFE")
            with s2:
                st.metric(
                    "High",
                    sum(1 for r in static_results if r.get('issue_severity') == 'HIGH')
                )
            with s3:
                st.metric(
                    "Medium",
                    sum(1 for r in static_results if r.get('issue_severity') == 'MEDIUM')
                )
            with s4:
                st.metric(
                    "Low",
                    sum(1 for r in static_results if r.get('issue_severity') == 'LOW')
                )

            # PDF download
            st.markdown("---")
            pdf_path = generate_pdf(code, actual_language, verdict, vuln_prob, static_results)
            
            with open(pdf_path, 'rb') as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name=f"guardai_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            os.unlink(pdf_path)

        elif scan_btn:
            st.warning("Please paste some code before scanning.")
        else:
            st.info("Paste code on the left and click Scan")
            st.markdown("**Example - SQL Injection (Python):**")
            st.code(
                'import sqlite3\n\n'
                'def get_user(name):\n'
                '    conn = sqlite3.connect("db")\n'
                '    query = "SELECT * FROM users WHERE name=\'" + name + "\'"\n'
                '    return conn.execute(query)',
                language='python'
            )
            st.markdown("**Example - eval() Injection (JavaScript):**")
            st.code(
                'function calculate(input) {\n'
                '    return eval(input);\n'
                '}',
                language='javascript'
            )

# ─────────────────────────────────────────────────────────
# TAB 2 - Project Scan
# ─────────────────────────────────────────────────────────
with tab2:
    st.subheader("Scan Entire Project")
    st.caption(
        "Upload a .zip file of your project. "
        "All Python files will be scanned with Bandit + AI. "
        "Other languages scanned with Semgrep + AI."
    )

    uploaded = st.file_uploader(
        "Upload project zip file",
        type=['zip'],
        key="project_upload"
    )

    if uploaded and st.button(
        "Scan Project",
        type="primary",
        key="project_scan"
    ):
        tokenizer, ai_model = load_model()

        with st.spinner("Scanning all files..."):
            zf = zipfile.ZipFile(io.BytesIO(uploaded.read()))
            supported_ext = {
                '.py', '.js', '.ts', '.php',
                '.java', '.go', '.rb', '.c', '.cpp'
            }
            all_files = [
                f for f in zf.namelist()
                if os.path.splitext(f)[1].lower() in supported_ext
                and '__pycache__' not in f
                and '.git' not in f
            ]

            if not all_files:
                st.error("No supported files found in the zip.")
                st.stop()

            st.info(f"Found **{len(all_files)}** files - scanning...")

            all_findings = []
            ai_scores    = []
            progress_bar = st.progress(0)
            status_text  = st.empty()

            ext_to_lang = {
                '.py': 'Python', '.js': 'JavaScript',
                '.ts': 'JavaScript', '.php': 'PHP',
                '.java': 'Java', '.go': 'Go',
                '.rb': 'Ruby', '.c': 'C', '.cpp': 'C++'
            }

            for idx, fname in enumerate(all_files):
                status_text.text(f"Scanning: {fname}")
                try:
                    code_text = zf.read(fname).decode('utf-8', errors='ignore')
                except Exception:
                    continue

                ext  = os.path.splitext(fname)[1].lower()
                lang = ext_to_lang.get(ext, 'Python')

                findings = scan_code(code_text, lang)
                all_findings.extend([
                    {**f, 'filename': fname, 'lang': lang}
                    for f in findings
                ])

                if tokenizer and ai_model and len(code_text.strip()) > 30:
                    _, _, vp = predict(code_text, tokenizer, ai_model)
                    ai_scores.append({'file': fname, 'score': vp, 'lang': lang})

                progress_bar.progress((idx + 1) / len(all_files))

            status_text.text("Scan complete.")

        # Project metrics
        total_high   = sum(1 for f in all_findings if f.get('issue_severity') == 'HIGH')
        total_medium = sum(1 for f in all_findings if f.get('issue_severity') == 'MEDIUM')
        total_low    = sum(1 for f in all_findings if f.get('issue_severity') == 'LOW')
        security_score = max(
            0,
            100 - (total_high * 15) - (total_medium * 7) - (total_low * 3)
        )

        st.markdown("---")
        st.markdown("### Project Security Score")
        p1, p2, p3, p4, p5 = st.columns(5)
        with p1:
            st.metric("Security Score", f"{security_score}/100")
        with p2:
            st.metric("Files Scanned", len(all_files))
        with p3:
            st.metric("High Issues",   total_high)
        with p4:
            st.metric("Medium Issues", total_medium)
        with p5:
            st.metric("Low Issues",    total_low)

        if security_score >= 80:
            st.success("Project is in good security health")
        elif security_score >= 60:
            st.warning("Project has security issues that need attention")
        else:
            st.error("Project has critical issues - do not deploy until fixed")

        # AI risk by file
        if ai_scores:
            st.markdown("### AI Risk by File (Top 10)")
            top_files = sorted(
                ai_scores, key=lambda x: x['score'], reverse=True
            )[:10]
            for item in top_files:
                col_f, col_p, col_s = st.columns([3, 2, 1])
                with col_f:
                    st.text(item['file'])
                with col_p:
                    st.progress(float(item['score']))
                with col_s:
                    st.caption(f"{item['score']*100:.1f}%")

        # All findings
        if all_findings:
            st.markdown("### All Findings")
            sev_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
            sorted_findings = sorted(
                all_findings,
                key=lambda x: sev_order.get(x.get('issue_severity', 'LOW'), 3)
            )
            for finding in sorted_findings:
                fname    = finding.get('filename', '')
                severity = finding.get('issue_severity', '')
                text     = finding.get('issue_text', '')
                line     = finding.get('line_number', '')
                test_id  = finding.get('test_id', '')
                lang     = finding.get('lang', '')
                _, owasp_name, fix = get_owasp(test_id)

                with st.expander(
                    f"{severity} - {fname} - Line {line}",
                    expanded=(severity == 'HIGH')
                ):
                    st.markdown(f"**File     :** `{fname}`")
                    st.markdown(f"**Language :** {lang}")
                    st.markdown(f"**Line     :** {line}")
                    st.markdown(f"**Severity :** {severity}")
                    st.markdown(f"**Issue    :** {text}")
                    st.markdown(f"**OWASP    :** {owasp_name}")
                    st.success(f"**Fix      :** {fix}")
        else:
            st.success("No issues found in the project")

# ── Footer ────────────────────────────────────────────────
st.markdown("---")
st.caption(
    "GuardAI v1.0 | Open source defensive security tool | "
    "UniXcoder + VulGate (184k CVE samples) | "
    "For authorized security assessments only | "
    "Never scan systems without written permission"
)