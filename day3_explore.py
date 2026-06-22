"""
GuardAI — Day 3
Goal: Download CVEfixes, explore what is inside it, understand
      what vulnerable code actually looks like vs fixed code.
Run: python day3_explore.py
"""

import sqlite3
import pandas as pd
import os

DB_PATH = "Data/CVEfixes.db"

def check_database():
    if not os.path.exists(DB_PATH):
        print("ERROR: CVEfixes.db not found.")
        print("Download it from: https://zenodo.org/record/7029359")
        print("Place it inside the Data/ folder")
        return False
    print(f"Database found at {DB_PATH}")
    return True

def explore_tables(conn):
    print("\n=== STEP 1: TABLES IN DATABASE ===")
    tables = pd.read_sql(
        "SELECT name FROM sqlite_master WHERE type='table'", conn
    )
    print(tables.to_string(index=False))

def explore_languages(conn):
    print("\n=== STEP 2: SAMPLES PER LANGUAGE ===")
    df = pd.read_sql("""
        SELECT
            programming_language       AS language,
            COUNT(*)                   AS total,
            SUM(CASE WHEN before_fix IS NOT NULL
                THEN 1 ELSE 0 END)     AS vulnerable
        FROM file_change
        GROUP BY programming_language
        ORDER BY total DESC
        LIMIT 15
    """, conn)
    print(df.to_string(index=False))
    return df

def explore_cves(conn):
    print("\n=== STEP 3: CVE COVERAGE ===")
    result = pd.read_sql(
        "SELECT COUNT(DISTINCT cve_id) AS total_cves FROM cve", conn
    )
    print(f"Total CVEs covered: {result['total_cves'][0]}")

def explore_cwe_types(conn):
    print("\n=== STEP 4: TOP VULNERABILITY TYPES (CWE) ===")
    df = pd.read_sql("""
        SELECT
            cwe_id,
            COUNT(*) AS count
        FROM cve
        WHERE cwe_id IS NOT NULL
        GROUP BY cwe_id
        ORDER BY count DESC
        LIMIT 15
    """, conn)
    print(df.to_string(index=False))

    print("\n--- What these CWE types mean ---")
    cwe_meanings = {
        "CWE-79":  "XSS — attacker injects script into your web page",
        "CWE-89":  "SQL Injection — attacker reads/deletes your database",
        "CWE-119": "Buffer Overflow — attacker crashes or controls your program",
        "CWE-200": "Info Exposure — sensitive data leaked to attacker",
        "CWE-416": "Use After Free — memory bug in C/C++ code",
        "CWE-125": "Out of Bounds Read — reads memory it shouldn't",
        "CWE-20":  "Improper Input Validation — trusts user input blindly",
        "CWE-22":  "Path Traversal — attacker reads files outside web root",
        "CWE-352": "CSRF — forces user to do actions without consent",
        "CWE-78":  "Command Injection — attacker runs OS commands",
    }
    for cwe, meaning in cwe_meanings.items():
        print(f"  {cwe:10s} → {meaning}")

def show_sample_vulnerable_code(conn, language="Python"):
    print(f"\n=== STEP 5: SAMPLE VULNERABLE {language} FUNCTION ===")
    df = pd.read_sql(f"""
        SELECT
            f.before_fix          AS vulnerable_code,
            f.after_fix           AS fixed_code,
            c.cwe_id,
            c.cvss_score,
            f.programming_language
        FROM file_change f
        JOIN fixes fx ON f.hash = fx.hash
        JOIN cve c    ON fx.cve_id = c.cve_id
        WHERE f.programming_language = '{language}'
        AND   f.before_fix IS NOT NULL
        AND   LENGTH(f.before_fix) > 100
        AND   LENGTH(f.before_fix) < 800
        LIMIT 3
    """, conn)

    if df.empty:
        print(f"No {language} samples found. Try another language.")
        return

    for i, row in df.iterrows():
        print(f"\n--- Sample {i+1} ---")
        print(f"Vulnerability type : {row['cwe_id']}")
        print(f"Severity score     : {row['cvss_score']} / 10.0")
        print(f"\nVULNERABLE CODE (what hackers exploit):")
        print("-" * 50)
        print(row['vulnerable_code'][:600])
        print(f"\nFIXED CODE (what developers should write):")
        print("-" * 50)
        print(row['fixed_code'][:600])
        print()

def build_quick_stats(conn):
    print("\n=== STEP 6: QUICK STATS FOR YOUR PROJECT ===")
    stats = pd.read_sql("""
        SELECT
            f.programming_language AS language,
            COUNT(*)               AS vulnerable_functions,
            AVG(c.cvss_score)      AS avg_severity
        FROM file_change f
        JOIN fixes fx ON f.hash = fx.hash
        JOIN cve c    ON fx.cve_id = c.cve_id
        WHERE f.before_fix IS NOT NULL
        AND   f.programming_language IN
              ('JavaScript','PHP','Java','Python','Go')
        GROUP BY f.programming_language
        ORDER BY vulnerable_functions DESC
    """, conn)
    print(stats.to_string(index=False))
    total = stats['vulnerable_functions'].sum()
    print(f"\nTotal training samples available (5 languages): {total:,}")
    print(f"With safe samples added (1:1 ratio)           : {total*2:,}")


def main():
    print("=" * 60)
    print("  GuardAI — Day 3: Dataset Exploration")
    print("=" * 60)

    if not check_database():
        return

    conn = sqlite3.connect(DB_PATH)

    explore_tables(conn)
    explore_languages(conn)
    explore_cves(conn)
    explore_cwe_types(conn)
    show_sample_vulnerable_code(conn, "Python")
    show_sample_vulnerable_code(conn, "JavaScript")
    build_quick_stats(conn)

    conn.close()

    print("\n" + "=" * 60)
    print("  Day 3 Complete.")
    print("  What to do now:")
    print("  1. Read 10 vulnerable code samples manually")
    print("  2. Look up the top 5 CWE types on cwe.mitre.org")
    print("  3. Understand the difference between before/after fix")
    print("  When ready → run day4_extract.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
