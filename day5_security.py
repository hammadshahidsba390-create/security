"""
GuardAI — Day 5
Goal: Protect YOUR OWN tool from being hacked.
      Every function here is a security layer that prevents
      attackers from abusing GuardAI to harm others.
Run: python day5_security.py (to test all protections)
"""

import os
import re
import time
import uuid
import hashlib
import logging
import mimetypes
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────
# LAYER 1: LOGGING — know everything that happens
# ─────────────────────────────────────────────

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/guardai_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("GuardAI")


# ─────────────────────────────────────────────
# LAYER 2: INPUT VALIDATION
# Block anything dangerous before it reaches your model
# ─────────────────────────────────────────────

# Maximum allowed file size: 500KB
# Prevents attackers uploading huge files to crash your server
MAX_FILE_SIZE_BYTES = 500 * 1024

# Only these file extensions are allowed
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".php",
    ".java", ".go", ".rb", ".c",
    ".cpp", ".cs", ".txt"
}

# These patterns in code suggest someone is trying to abuse your scanner
# An attacker might submit code that tries to escape the sandbox
DANGEROUS_PATTERNS = [
    r"__import__\s*\(",          # Python dynamic import
    r"eval\s*\(",                # eval() in any language
    r"exec\s*\(",                # exec() in Python
    r"subprocess\.",             # subprocess calls
    r"os\.system\s*\(",          # shell execution
    r"Runtime\.getRuntime",      # Java shell execution
    r"Process\.Start",           # C# shell execution
    r"\bshell_exec\b",           # PHP shell execution
    r"\bpassthru\b",             # PHP shell execution
    r"\/etc\/passwd",            # Linux file traversal attempt
    r"\.\.\/"                    # Path traversal attempt
]

def validate_file_upload(filename: str, content: str) -> dict:
    """
    Validates a file before any processing.
    Returns: {"valid": True/False, "reason": "why it failed"}
    """
    # Check file extension
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        logger.warning(f"Blocked upload: invalid extension {ext}")
        return {
            "valid": False,
            "reason": f"File type {ext} not supported. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        }

    # Check file size
    size = len(content.encode("utf-8"))
    if size > MAX_FILE_SIZE_BYTES:
        logger.warning(f"Blocked upload: file too large ({size} bytes)")
        return {
            "valid": False,
            "reason": f"File too large ({size/1024:.1f}KB). Maximum: {MAX_FILE_SIZE_BYTES/1024:.0f}KB"
        }

    # Check for empty file
    if len(content.strip()) < 10:
        return {"valid": False, "reason": "File is empty or too short"}

    # Check for abuse patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, content):
            logger.warning(f"Blocked upload: dangerous pattern detected: {pattern}")
            return {
                "valid": False,
                "reason": "File contains patterns that cannot be processed for security reasons"
                # Note: don't tell attacker WHICH pattern matched
            }

    logger.info(f"File validated: {filename} ({size} bytes)")
    return {"valid": True, "reason": "OK"}


# ─────────────────────────────────────────────
# LAYER 3: RATE LIMITING
# Prevents someone hammering your API 10,000 times
# ─────────────────────────────────────────────

class RateLimiter:
    """
    Tracks requests per user.
    Blocks users who exceed the limit within a time window.
    """
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests   = max_requests    # max 10 scans per minute per user
        self.window_seconds = window_seconds
        self.requests       = defaultdict(list)  # user_id → [timestamps]

    def is_allowed(self, user_id: str) -> dict:
        now = time.time()
        window_start = now - self.window_seconds

        # Remove old timestamps outside current window
        self.requests[user_id] = [
            t for t in self.requests[user_id]
            if t > window_start
        ]

        # Check if over limit
        if len(self.requests[user_id]) >= self.max_requests:
            wait_time = int(self.window_seconds - (now - self.requests[user_id][0]))
            logger.warning(f"Rate limit hit for user: {user_id}")
            return {
                "allowed": False,
                "reason": f"Too many requests. Please wait {wait_time} seconds."
            }

        # Record this request
        self.requests[user_id].append(now)
        remaining = self.max_requests - len(self.requests[user_id])
        return {
            "allowed": True,
            "remaining": remaining,
            "reason": "OK"
        }


# Single global rate limiter instance
rate_limiter = RateLimiter(max_requests=10, window_seconds=60)


# ─────────────────────────────────────────────
# LAYER 4: SECRETS MANAGEMENT
# Never hardcode API keys or passwords in your code
# ─────────────────────────────────────────────

def get_secret(key: str, default: str = None) -> str:
    """
    Always read secrets from environment variables.
    NEVER hardcode them in your code.

    How to set them:
      Linux/Mac: export GUARDAI_SECRET_KEY="your-secret-here"
      Windows:   set GUARDAI_SECRET_KEY=your-secret-here

    How to use in this code:
      secret = get_secret("GUARDAI_SECRET_KEY")
    """
    value = os.environ.get(key, default)
    if value is None:
        logger.error(f"Missing required secret: {key}")
        raise ValueError(
            f"Environment variable {key} not set. "
            f"Run: export {key}='your-value-here'"
        )
    return value


def generate_api_key() -> str:
    """
    Generates a unique API key for each company that signs up.
    Store these in a database, not in your code.
    """
    return str(uuid.uuid4()).replace("-", "")


# ─────────────────────────────────────────────
# LAYER 5: SANDBOXED CODE ANALYSIS
# Your scanner READS code — it must NEVER EXECUTE it
# ─────────────────────────────────────────────

def safe_analyze_code(code: str, language: str) -> dict:
    """
    Analyzes code safely WITHOUT executing it.
    This is a stub — your real CodeBERT model goes here.
    The key rule: we pass code as STRING to the model.
    We NEVER use eval(), exec(), or subprocess to run it.
    """
    # CORRECT: pass code as text to model
    # model.predict(tokenizer(code))  ← safe, just text processing

    # WRONG — never do any of these:
    # eval(code)                ← executes the code
    # exec(code)                ← executes the code
    # subprocess.run(code)      ← executes the code

    # Stub result — replace with real model in Day 8
    return {
        "language":   language,
        "code_length": len(code),
        "analyzed":   True,
        "method":     "static_analysis_only"
    }


# ─────────────────────────────────────────────
# LAYER 6: AUDIT LOGGING
# Every scan is logged with who did it and when
# ─────────────────────────────────────────────

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def log_scan_request(
    user_id:  str,
    filename: str,
    language: str,
    code_hash: str
) -> str:
    """
    Logs every scan request.
    Returns a unique scan ID for tracking.
    """
    scan_id = str(uuid.uuid4())[:8].upper()
    logger.info(
        f"SCAN | id={scan_id} | user={user_id} | "
        f"file={filename} | lang={language} | "
        f"hash={code_hash[:12]}..."
    )
    return scan_id


def log_scan_result(
    scan_id:  str,
    findings: list,
    duration: float
) -> None:
    """
    Logs what the scan found.
    Findings are logged but NOT stored permanently with the actual code.
    """
    logger.info(
        f"RESULT | id={scan_id} | "
        f"findings={len(findings)} | "
        f"duration={duration:.2f}s"
    )


def hash_code(code: str) -> str:
    """
    Creates a hash of the submitted code.
    We log the hash (for dedup/tracking) but not the raw code.
    Protects user's intellectual property.
    """
    return hashlib.sha256(code.encode()).hexdigest()


# ─────────────────────────────────────────────
# LAYER 7: RESPONSIBLE DISCLOSURE POLICY
# What your tool does and does not do with findings
# ─────────────────────────────────────────────

RESPONSIBLE_DISCLOSURE_POLICY = """
GuardAI Responsible Disclosure Policy
======================================

WHAT WE DO:
- Scan code submitted by the authorized user
- Return findings only to the submitting user
- Log scan metadata (timestamp, file hash, language) for security
- Delete submitted code from memory after scan completes

WHAT WE DO NOT DO:
- Store the actual submitted source code permanently
- Share findings with any third party
- Scan code outside the authorized scope
- Execute submitted code in any way
- Use submitted code to train our models without explicit consent

YOUR RESPONSIBILITIES:
- Only submit code you own or have authorization to scan
- Do not submit code containing real credentials or secrets
- Use findings responsibly to fix vulnerabilities, not exploit them

BREACH REPORTING:
If you discover a vulnerability in GuardAI itself, please report it to:
guardai-security@yourdomain.com
We commit to responding within 48 hours.
"""


# ─────────────────────────────────────────────
# COMPLETE SCAN PIPELINE — all protections applied
# ─────────────────────────────────────────────

def secure_scan(
    user_id:  str,
    filename: str,
    code:     str,
    language: str
) -> dict:
    """
    The complete secure scan pipeline.
    Every request goes through all 6 protection layers.
    """
    start_time = time.time()

    # Layer 3: Rate limit check
    rate_check = rate_limiter.is_allowed(user_id)
    if not rate_check["allowed"]:
        return {"error": rate_check["reason"], "scan_id": None}

    # Layer 2: Input validation
    validation = validate_file_upload(filename, code)
    if not validation["valid"]:
        return {"error": validation["reason"], "scan_id": None}

    # Layer 6: Audit log — start
    code_hash = hash_code(code)
    scan_id   = log_scan_request(user_id, filename, language, code_hash)

    # Layer 5: Safe analysis (no execution)
    result = safe_analyze_code(code, language)

    # Stub findings — your real model replaces this in Day 8
    findings = [
        {
            "line":     42,
            "severity": "HIGH",
            "cwe":      "CWE-89",
            "message":  "Potential SQL injection — user input used in query",
            "fix":      "Use parameterized queries instead of string concatenation"
        }
    ]

    duration = time.time() - start_time

    # Layer 6: Audit log — result
    log_scan_result(scan_id, findings, duration)

    return {
        "scan_id":   scan_id,
        "language":  language,
        "findings":  findings,
        "duration":  round(duration, 3),
        "policy":    "Submitted code is not stored permanently."
    }


# ─────────────────────────────────────────────
# SELF-TEST — run this to verify all protections work
# ─────────────────────────────────────────────

def run_self_tests():
    print("\n=== GUARDAI SECURITY SELF-TEST ===\n")

    # Test 1: Valid file
    result = validate_file_upload(
        "login.py",
        "def login(user): return db.query(user)"
    )
    status = "PASS" if result["valid"] else "FAIL"
    print(f"[{status}] Valid Python file accepted")

    # Test 2: Invalid extension
    result = validate_file_upload("malware.exe", "some content")
    status = "PASS" if not result["valid"] else "FAIL"
    print(f"[{status}] .exe file blocked")

    # Test 3: Dangerous pattern
    result = validate_file_upload(
        "test.py",
        "import os; os.system('rm -rf /')"
    )
    status = "PASS" if not result["valid"] else "FAIL"
    print(f"[{status}] os.system() pattern blocked")

    # Test 4: Path traversal attempt
    result = validate_file_upload(
        "test.php",
        "include('../../../etc/passwd')"
    )
    status = "PASS" if not result["valid"] else "FAIL"
    print(f"[{status}] Path traversal blocked")

    # Test 5: Rate limiting
    user = "test_user_001"
    blocked = False
    for i in range(15):
        check = rate_limiter.is_allowed(user)
        if not check["allowed"]:
            blocked = True
            break
    status = "PASS" if blocked else "FAIL"
    print(f"[{status}] Rate limiting blocks after 10 requests")

    # Test 6: Full secure scan pipeline
    scan = secure_scan(
        user_id  = "company_abc",
        filename = "views.py",
        code     = "def get_user(id): return db.query('SELECT * FROM users WHERE id=' + id)",
        language = "Python"
    )
    status = "PASS" if scan.get("scan_id") else "FAIL"
    print(f"[{status}] Full scan pipeline works")

    print("\n=== ALL TESTS COMPLETE ===")
    print("Check logs/ folder to see the audit trail")


if __name__ == "__main__":
    run_self_tests()
    print("\n" + "=" * 60)
    print("  Day 5 Complete.")
    print("  What to do now:")
    print("  1. Read each protection layer — understand WHY it exists")
    print("  2. Check logs/ folder — see what gets logged")
    print("  3. Try breaking it yourself — submit a .exe file")
    print("  When ready → Day 6 is installing the static analysis tools")
    print("=" * 60)
