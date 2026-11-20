import os
import sys
import re
import time
import socket
import smtplib
import argparse
from datetime import datetime
import pandas as pd
import dns.resolver
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def find_email_column(df):
    for col in df.columns:
        if 'email' in col.lower():
            return col
    raise ValueError(f"Could not find an email column in CSV. Available columns: {list(df.columns)}")

def check_syntax(email):
    if not isinstance(email, str) or not email.strip():
        return False
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(regex, email.strip()))

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
    except Exception:
        return []

def smtp_check_gmail(email, mx_host):
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((mx_host, 25))
        server = smtplib.SMTP()
        server.sock = sock
        server.file = sock.makefile('rb')
        code, msg = server.getreply()
        if code != 220:
            server.close()
            return "unknown", f"Initial banner code {code}"
            
        server.helo('check.local')
        server.mail('verify@check.local')
        rcpt_code, rcpt_msg = server.rcpt(email)
        server.quit()
        msg_str = rcpt_msg.decode('utf-8', errors='ignore')
        
        if rcpt_code == 250:
            return "deliverable", "Google SMTP 250 OK: Mailbox exists"
        elif rcpt_code in (550, 551, 553):
            return "undeliverable", f"Google SMTP {rcpt_code}: Mailbox does not exist ({msg_str})"
        elif rcpt_code == 552:
            return "undeliverable", f"Google SMTP 552: Mailbox over quota ({msg_str})"
        else:
            return "unknown", f"Google SMTP {rcpt_code}: {msg_str}"
    except Exception as e:
        return "unknown", f"Google SMTP connection failed: {str(e)}"

def verify_microsoft_batch(emails):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    post_headers = {
        "User-Agent": headers["User-Agent"],
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "hpgact": "0",
        "hpgid": "33"
    }

    def get_session():
        s = requests.Session()
        try:
            r = s.get("https://login.live.com/", headers=headers, timeout=10)
            m = re.search(r'sFTTag["\']?\s*:\s*["\'].*?value=\\"([^\\"]+)\\"', r.text)
            if not m:
                m = re.search(r'value="([^"]+)"\s+name="PPFT"', r.text)
            token = m.group(1) if m else None
            return s, token
        except Exception:
            return s, None

    results = {}
    s, token = get_session()

    for em in emails:
        status, reason = "unknown", "Could not verify"
        for attempt in range(2):
            if not token:
                s, token = get_session()
            payload = {
                "username": em,
                "isOtherIdpSupported": True,
                "checkPhones": False,
                "isRemoteNGCSupported": True,
                "isFidoSupported": True,
                "countryCode": "US",
                "forceotclogin": False,
                "isExternalFederationDisallowed": False,
                "isRemoteConnectSupported": False,
                "federationFlags": 0,
                "isSignup": False,
                "flowToken": token
            }
            try:
                r = s.post("https://login.live.com/GetCredentialType.srf", headers=post_headers, json=payload, timeout=10)
                data = r.json()
                if_exists = data.get("IfExistsResult")
                if data.get("FlowToken"):
                    token = data.get("FlowToken")
                if if_exists == 0:
                    status = "deliverable"
                    reason = "Microsoft Live enumeration: Account exists (IfExistsResult=0)"
                    break
                elif if_exists == 1:
                    status = "undeliverable"
                    reason = "Microsoft Live enumeration: Mailbox purged/does not exist (IfExistsResult=1)"
                    break
                else:
                    s, token = get_session()
                    time.sleep(1)
            except Exception:
                s, token = get_session()
                time.sleep(1)
        results[em] = (status, reason)
        time.sleep(0.8)
    return results

def verify_yahoo_batch(emails):
    if not emails:
        return {}
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,800")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    driver = webdriver.Chrome(options=options)
    results = {}
    try:
        for idx, em in enumerate(emails):
            status = "unknown"
            reason = "Page evaluation timeout"
            try:
                driver.get("https://login.yahoo.com/")
                username_field = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "username"))
                )
                username_field.clear()
                username_field.send_keys(em)
                time.sleep(0.8)
                username_field.send_keys(Keys.ENTER)
                time.sleep(3.5)

                current_url = driver.current_url
                page_text = driver.find_element(By.TAG_NAME, "body").text.lower()

                if "we don't recognize" in page_text or "sorry, we don't" in page_text or "doesn't exist" in page_text:
                    status = "undeliverable"
                    reason = "Yahoo account does not exist / purged due to inactivity"
                elif "/account/challenge" in current_url or "password" in page_text or "/password" in current_url or "yak-code" in current_url:
                    status = "deliverable"
                    reason = "Yahoo account exists and active (prompted challenge/password)"
                elif "too many attempts" in page_text:
                    status = "unknown"
                    reason = "Yahoo edge rate limit reached"
                    break
            except Exception as e:
                status = "unknown"
                reason = f"Yahoo automated check exception: {str(e)}"
            results[em] = (status, reason)
            print(f"  [{idx+1}/{len(emails)}] {em:<35} -> {status.upper()}")
            time.sleep(1.8)
    finally:
        driver.quit()
    return results

def run_validation(input_csv, custom_output_dir=None, clean_status="sent"):
    if not os.path.exists(input_csv):
        print(f"Error: File '{input_csv}' not found.")
        sys.exit(1)

    df = pd.read_csv(input_csv)
    email_col = find_email_column(df)
    print(f"\n[+] Loaded '{input_csv}' with {len(df)} rows. Using email column: '{email_col}'")

    # Create timestamped output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(os.path.basename(input_csv))[0]
    out_dir = custom_output_dir if custom_output_dir else f"output_{base_name}_{timestamp}"
    os.makedirs(out_dir, exist_ok=True)
    print(f"[+] Dedicated Output Folder Created: {os.path.abspath(out_dir)}")

    df["Email Status"] = "unknown"
    df["Email Confidence"] = 0
    df["SMTP Result"] = "unknown"
    df["Detailed_Reason"] = ""

    # Tier 1: Syntax & MX lookup
    print("\n--- Tier 1: Syntax & MX Verification ---")
    mx_cache = {}
    emails_to_check = []
    
    for idx, row in df.iterrows():
        raw_val = row[email_col]
        if pd.isna(raw_val) or not str(raw_val).strip():
            df.at[idx, "Email Status"] = "invalid"
            df.at[idx, "Email Confidence"] = 0
            df.at[idx, "SMTP Result"] = "missing_email"
            df.at[idx, "Detailed_Reason"] = "No email address provided in record"
            continue
            
        raw_email = str(raw_val).strip()
        if not check_syntax(raw_email):
            df.at[idx, "Email Status"] = "invalid"
            df.at[idx, "Email Confidence"] = 0
            df.at[idx, "SMTP Result"] = "invalid_syntax"
            df.at[idx, "Detailed_Reason"] = f"Syntax format is invalid: '{raw_email}'"
            continue

        domain = raw_email.split('@')[1].lower()
        if domain not in mx_cache:
            mx_cache[domain] = get_mx_records(domain)
        
        mx_records = mx_cache[domain]
        if not mx_records:
            df.at[idx, "Email Status"] = "invalid"
            df.at[idx, "Email Confidence"] = 0
            df.at[idx, "SMTP Result"] = "no_mx"
            df.at[idx, "Detailed_Reason"] = f"Domain '{domain}' has no active MX records"
            continue

        emails_to_check.append((idx, raw_email, domain, mx_records))

    print(f"  Valid syntax & MX passed: {len(emails_to_check)} / {len(df)}")

    # Classify providers
    gmail_queue = []
    ms_queue = []
    yahoo_queue = []
    other_queue = []

    for idx, email, domain, mx_records in emails_to_check:
        top_mx = mx_records[0][1].lower()
        if "google.com" in top_mx or "googlemail.com" in top_mx:
            gmail_queue.append((idx, email, top_mx))
        elif any(d in domain for d in ["hotmail.", "live.", "msn.", "outlook."]):
            ms_queue.append((idx, email))
        elif any(d in domain for d in ["yahoo.", "ymail.", "aol.", "verizon.", "att."]) or "yahoodns.net" in top_mx:
            yahoo_queue.append((idx, email))
        elif "outlook.com" in top_mx or "microsoft.com" in top_mx:
            other_queue.append((idx, email, "M365", top_mx))
        else:
            other_queue.append((idx, email, "OTHER", top_mx))

    # Tier 2: Gmail SMTP Handshake
    print(f"\n--- Tier 2: Google / Workspace SMTP Handshake ({len(gmail_queue)} addresses) ---")
    for idx, em, top_mx in gmail_queue:
        res, reason = smtp_check_gmail(em, top_mx)
        if res == "deliverable":
            df.at[idx, "Email Status"] = "safe"
            df.at[idx, "Email Confidence"] = 99
            df.at[idx, "SMTP Result"] = "deliverable"
            df.at[idx, "Detailed_Reason"] = reason
        elif res == "undeliverable":
            df.at[idx, "Email Status"] = "invalid"
            df.at[idx, "Email Confidence"] = 0
            df.at[idx, "SMTP Result"] = "undeliverable"
            df.at[idx, "Detailed_Reason"] = reason
        else:
            df.at[idx, "Email Status"] = "risky"
            df.at[idx, "Email Confidence"] = 50
            df.at[idx, "SMTP Result"] = "unknown"
            df.at[idx, "Detailed_Reason"] = reason
        print(f"  {em:<35} -> {df.at[idx, 'Email Status'].upper()}")

    # Tier 3: Microsoft Directory Live API
    print(f"\n--- Tier 3: Microsoft Live Directory API ({len(ms_queue)} addresses) ---")
    if ms_queue:
        ms_res = verify_microsoft_batch([em for _, em in ms_queue])
        for idx, em in ms_queue:
            res, reason = ms_res.get(em, ("unknown", "No response"))
            if res == "deliverable":
                df.at[idx, "Email Status"] = "safe"
                df.at[idx, "Email Confidence"] = 98
                df.at[idx, "SMTP Result"] = "deliverable"
                df.at[idx, "Detailed_Reason"] = reason
            elif res == "undeliverable":
                df.at[idx, "Email Status"] = "invalid"
                df.at[idx, "Email Confidence"] = 0
                df.at[idx, "SMTP Result"] = "undeliverable"
                df.at[idx, "Detailed_Reason"] = reason
            else:
                df.at[idx, "Email Status"] = "risky"
                df.at[idx, "Email Confidence"] = 45
                df.at[idx, "SMTP Result"] = "unknown"
                df.at[idx, "Detailed_Reason"] = reason
            print(f"  {em:<35} -> {df.at[idx, 'Email Status'].upper()}")

    # Tier 4: Yahoo / AOL Headless Chrome Automation
    print(f"\n--- Tier 4: Yahoo / AOL Automated Web Check ({len(yahoo_queue)} addresses) ---")
    if yahoo_queue:
        yahoo_res = verify_yahoo_batch([em for _, em in yahoo_queue])
        for idx, em in yahoo_queue:
            res, reason = yahoo_res.get(em, ("unknown", "No response"))
            if res == "deliverable":
                df.at[idx, "Email Status"] = "safe"
                df.at[idx, "Email Confidence"] = 98
                df.at[idx, "SMTP Result"] = "deliverable"
                df.at[idx, "Detailed_Reason"] = reason
            elif res == "undeliverable":
                df.at[idx, "Email Status"] = "invalid"
                df.at[idx, "Email Confidence"] = 0
                df.at[idx, "SMTP Result"] = "undeliverable"
                df.at[idx, "Detailed_Reason"] = reason
            else:
                df.at[idx, "Email Status"] = "risky"
                df.at[idx, "Email Confidence"] = 40
                df.at[idx, "SMTP Result"] = "unknown"
                df.at[idx, "Detailed_Reason"] = reason

    # Tier 5: Other custom domains
    print(f"\n--- Tier 5: Remaining Custom / ISP Domains ({len(other_queue)} addresses) ---")
    for idx, em, kind, top_mx in other_queue:
        df.at[idx, "Email Status"] = "risky"
        df.at[idx, "Email Confidence"] = 60
        df.at[idx, "SMTP Result"] = "unverified"
        df.at[idx, "Detailed_Reason"] = f"Domain MX valid ({top_mx}), mailbox check filtered by ISP port 25"
        print(f"  {em:<35} -> RISKY (Domain MX active)")

    # Partition and save files
    clean_df = df[df["Email Status"] == "safe"].copy()
    invalid_df = df[df["Email Status"] == "invalid"].copy()
    risky_df = df[df["Email Status"] == "risky"].copy()

    # Apply Status column if requested
    if clean_status is not None:
        clean_df["Status"] = str(clean_status)

    master_path = os.path.join(out_dir, f"{base_name}_validated.csv")
    clean_path = os.path.join(out_dir, "clean.csv")
    invalid_path = os.path.join(out_dir, "invalid.csv")
    risky_path = os.path.join(out_dir, "risky.csv")

    df.to_csv(master_path, index=False)
    clean_df.to_csv(clean_path, index=False)
    invalid_df.to_csv(invalid_path, index=False)
    risky_df.to_csv(risky_path, index=False)

    print("\n" + "="*60)
    print("VALIDATION PIPELINE COMPLETE")
    print("="*60)
    print(f"Total Rows Processed:  {len(df)}")
    print(f"  Clean / Deliverable: {len(clean_df)} (saved to: {clean_path})")
    if clean_status:
        print(f"    -> Added column 'Status' = '{clean_status}'")
    print(f"  Invalid / Bounced:   {len(invalid_df)} (saved to: {invalid_path})")
    print(f"  Risky / Unverified:  {len(risky_df)} (saved to: {risky_path})")
    print(f"  Full Master CSV:     {master_path}")
    print("="*60 + "\n")
    return out_dir

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full Turnkey Multi-Tier Email Validator")
    parser.add_argument("input_csv", help="Path to input CSV file")
    parser.add_argument("--output-dir", help="Custom output directory path (optional)", default=None)
    parser.add_argument("--clean-status", help="Set 'Status' column value in clean.csv", default="sent")
    args = parser.parse_args()

    run_validation(args.input_csv, args.output_dir, args.clean_status)
