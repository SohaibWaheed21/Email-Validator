"""
Workaround Script: Bulk Mailbox Validation for Yahoo & Hotmail via Free API.
Compatible with Hunter.io, ZeroBounce, Debounce, or AbstractAPI.

Usage:
    python verify_with_api.py --provider hunter --key YOUR_API_KEY
    python verify_with_api.py --provider zerobounce --key YOUR_API_KEY
    python verify_with_api.py --provider debounce --key YOUR_API_KEY
"""

import argparse
import time
from pathlib import Path
import pandas as pd
import requests

RISKY_FILE = Path("output/risky.csv")
MASTER_FILE = Path("plumb_validated.csv")
FINAL_OUT = Path("output/plumb_fully_verified.csv")

def verify_hunter(email, api_key):
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}"
    r = requests.get(url, timeout=10)
    if r.status_code == 200:
        data = r.json().get("data", {})
        status = data.get("status")  # valid, invalid, accept_all, webmail
        score = data.get("score", 0)
        is_safe = status == "valid" or (status == "webmail" and score >= 70)
        return is_safe, f"Hunter.io: {status} (score {score})"
    return None, f"Hunter.io error: HTTP {r.status_code}"

def verify_zerobounce(email, api_key):
    url = f"https://api.zerobounce.net/v2/validate?api_key={api_key}&email={email}"
    r = requests.get(url, timeout=10)
    if r.status_code == 200:
        data = r.json()
        status = data.get("status")  # valid, invalid, catch-all, unknown, spamtrap, abuse, do_not_mail
        sub = data.get("sub_status", "")
        is_safe = status == "valid"
        return is_safe, f"ZeroBounce: {status} ({sub})"
    return None, f"ZeroBounce error: HTTP {r.status_code}"

def verify_debounce(email, api_key):
    url = f"https://api.debounce.io/v1/?api={api_key}&email={email}"
    r = requests.get(url, timeout=10)
    if r.status_code == 200:
        data = r.json().get("debounce", {})
        code = data.get("code")  # 5: Safe to Send, 4: Risky, 2: Invalid
        reason = data.get("reason", "")
        is_safe = code == "5"
        return is_safe, f"Debounce code {code}: {reason}"
    return None, f"Debounce error: HTTP {r.status_code}"

def main():
    parser = argparse.ArgumentParser(description="Verify Yahoo/Hotmail emails via free API")
    parser.add_argument("--provider", choices=["hunter", "zerobounce", "debounce"], default="hunter", help="API service to use")
    parser.add_argument("--key", required=True, help="Your API key from the service")
    args = parser.parse_args()

    if not RISKY_FILE.exists():
        raise SystemExit(f"Missing {RISKY_FILE}. Run validate_plumb_complete.py first.")

    df_risky = pd.read_csv(RISKY_FILE)
    df_master = pd.read_csv(MASTER_FILE)

    print(f"Loaded {len(df_risky)} unverified emails from {RISKY_FILE} to verify via {args.provider.upper()}...")

    results = {}
    for idx, row in df_risky.iterrows():
        email = row['Email'].strip()
        print(f"[{idx+1}/{len(df_risky)}] Checking {email}...", end=" ", flush=True)

        if args.provider == "hunter":
            is_safe, reason = verify_hunter(email, args.key)
        elif args.provider == "zerobounce":
            is_safe, reason = verify_zerobounce(email, args.key)
        elif args.provider == "debounce":
            is_safe, reason = verify_debounce(email, args.key)

        print(f"-> {'SAFE' if is_safe else 'INVALID/RISKY'} ({reason})")
        results[email] = (is_safe, reason)
        time.sleep(0.3)

    # Update master file
    for email, (is_safe, reason) in results.items():
        mask = df_master['Email'] == email
        if is_safe is True:
            df_master.loc[mask, 'Validation'] = 'safe'
            df_master.loc[mask, 'Email Status'] = 'safe'
            df_master.loc[mask, 'Email Confidence'] = 90
            df_master.loc[mask, 'SMTP Result'] = 'deliverable'
            df_master.loc[mask, 'Detailed_Reason'] = reason
        elif is_safe is False:
            df_master.loc[mask, 'Validation'] = 'invalid'
            df_master.loc[mask, 'Email Status'] = 'invalid'
            df_master.loc[mask, 'Email Confidence'] = 0
            df_master.loc[mask, 'SMTP Result'] = 'rejected'
            df_master.loc[mask, 'Detailed_Reason'] = reason

    df_master.to_csv(FINAL_OUT, index=False, encoding='utf-8')
    print(f"\nFinished! Fully verified master list saved to: {FINAL_OUT.resolve()}")

    # Update clean and invalid
    clean = df_master[df_master['Validation'] == 'safe']
    invalid = df_master[df_master['Validation'] == 'invalid']
    clean.to_csv("output/clean_all_verified.csv", index=False, encoding='utf-8')
    invalid.to_csv("output/invalid_all_verified.csv", index=False, encoding='utf-8')
    print(f"Final safe leads: {len(clean)} -> output/clean_all_verified.csv")
    print(f"Final dead leads: {len(invalid)} -> output/invalid_all_verified.csv")

if __name__ == "__main__":
    main()
