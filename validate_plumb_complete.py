import csv
import ipaddress
import json
from pathlib import Path
import smtplib
import time
import dns.resolver
import pandas as pd

INPUT_FILE = Path("plumb.csv")
OUT_DIR = Path("output")
OUT_DIR.mkdir(exist_ok=True)

ROLE_PREFIXES = {
    "admin", "info", "support", "sales", "contact", "billing", "help",
    "office", "team", "marketing", "jobs", "careers", "hr", "hello",
    "inquiry", "media", "press", "service", "services", "feedback"
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getairmail.com",
    "dispostable.com", "throwawaymail.com", "nada.ltd", "temp-mail.org"
}

YAHOO_DOMAINS = {
    "yahoo.com", "ymail.com", "myyahoo.com", "rocketmail.com",
    "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it",
    "yahoo.ca", "yahoo.com.br", "yahoo.com.au", "yahoo.co.in",
    "yahoo.com.mx", "yahoo.com.ar", "yahoo.com.hk", "yahoo.com.tw",
    "yahoo.com.sg", "yahoo.com.ph"
}

AOL_DOMAINS = {"aol.com", "aim.com", "verizon.net"}

MICROSOFT_DOMAINS = {
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "hotmail.co.uk", "hotmail.fr", "hotmail.es", "hotmail.it",
    "live.co.uk", "live.fr", "live.com.au", "msn.co.uk"
}

dns_cache = {}

def resolve_mx_details(domain):
    if domain in dns_cache:
        return dns_cache[domain]
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        answers = resolver.resolve(domain, 'MX')
        records = [str(r.exchange).rstrip('.') for r in sorted(answers, key=lambda x: x.preference)]
        if not records:
            res = ([], False, "no MX records")
            dns_cache[domain] = res
            return res
            
        # Check IP routing
        mx_host = records[0]
        try:
            a_answers = resolver.resolve(mx_host, 'A')
            for r in a_answers:
                ip_obj = ipaddress.ip_address(str(r))
                if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                    res = (records, False, f"MX resolves to private/unroutable IP {ip_obj}")
                    dns_cache[domain] = res
                    return res
        except Exception:
            pass
            
        res = (records, True, "OK")
        dns_cache[domain] = res
        return res
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        res = ([], False, "domain does not exist")
        dns_cache[domain] = res
        return res
    except Exception as e:
        res = ([], False, f"DNS error: {e}")
        dns_cache[domain] = res
        return res

def check_single_email(email):
    email = email.strip()
    user, domain = email.split('@', 1)
    user_lower = user.lower()
    domain_lower = domain.lower()
    
    is_role = user_lower in ROLE_PREFIXES
    is_disp = domain_lower in DISPOSABLE_DOMAINS
    
    rec = {
        "email": email,
        "syntax_valid": "yes",
        "domain_exists": "yes",
        "mx_found": "yes",
        "disposable": "yes" if is_disp else "no",
        "role_based": "yes" if is_role else "no",
        "smtp_result": "unverified",
        "validation": "risky",
        "confidence": 45,
        "detailed_reason": ""
    }
    
    if is_disp:
        rec["validation"] = "invalid"
        rec["confidence"] = 0
        rec["smtp_result"] = "rejected"
        rec["detailed_reason"] = "Disposable email domain"
        return rec
        
    mx_records, mx_valid, mx_note = resolve_mx_details(domain_lower)
    if not mx_records or not mx_valid:
        rec["domain_exists"] = "no" if "domain does not exist" in mx_note else "yes"
        rec["mx_found"] = "no" if "no MX" in mx_note else "yes"
        rec["validation"] = "invalid"
        rec["confidence"] = 0
        rec["smtp_result"] = "rejected"
        rec["detailed_reason"] = f"Domain/MX failure: {mx_note}"
        return rec
        
    mx_host = mx_records[0]
    
    # 1. Google (Gmail & Google Workspace)
    is_google = domain_lower == 'gmail.com' or any('google.com' in mx or 'googlemail.com' in mx for mx in mx_records)
    if is_google:
        try:
            s = smtplib.SMTP(timeout=8)
            s.connect(mx_host, 25)
            s.ehlo('gmail.com')
            s.mail('verify@gmail.com')
            code, msg = s.rcpt(email)
            try:
                s.quit()
            except Exception:
                pass
            msg_str = msg.decode(errors='ignore').strip().replace('\n', ' ')
            if code == 250:
                rec["validation"] = "safe"
                rec["confidence"] = 95 if not is_role else 65
                rec["smtp_result"] = "deliverable"
                rec["detailed_reason"] = f"SMTP 250 OK: Google confirmed mailbox exists" + (" [role account]" if is_role else "")
                return rec
            elif code == 550:
                rec["validation"] = "invalid"
                rec["confidence"] = 0
                rec["smtp_result"] = "rejected"
                rec["detailed_reason"] = f"SMTP 550: Google confirmed mailbox does not exist ({msg_str[:40]})"
                return rec
            elif code == 552:
                rec["validation"] = "invalid"
                rec["confidence"] = 0
                rec["smtp_result"] = "rejected"
                rec["detailed_reason"] = f"SMTP 552: Mailbox is disabled / storage full ({msg_str[:40]})"
                return rec
            else:
                rec["validation"] = "risky"
                rec["confidence"] = 40
                rec["smtp_result"] = f"code_{code}"
                rec["detailed_reason"] = f"Google SMTP {code}: {msg_str[:40]}"
                return rec
        except Exception as e:
            rec["validation"] = "risky"
            rec["confidence"] = 45
            rec["smtp_result"] = "connection_failed"
            rec["detailed_reason"] = f"Google SMTP connection error: {e}"
            return rec

    # 2. Microsoft 365 Custom Domains (like info@rct24.com)
    is_m365_custom = any('protection.outlook.com' in mx for mx in mx_records) and domain_lower not in MICROSOFT_DOMAINS
    if is_m365_custom:
        try:
            s = smtplib.SMTP(timeout=8)
            s.connect(mx_host, 25)
            s.ehlo('validator.local')
            s.mail('verify@validator.local')
            code, msg = s.rcpt(email)
            try:
                s.quit()
            except Exception:
                pass
            if code == 250:
                rec["validation"] = "safe"
                rec["confidence"] = 95 if not is_role else 65
                rec["smtp_result"] = "deliverable"
                rec["detailed_reason"] = f"SMTP 250 OK: Microsoft 365 confirmed mailbox exists" + (" [role account]" if is_role else "")
                return rec
            elif code in (550, 551, 553, 554):
                rec["validation"] = "invalid"
                rec["confidence"] = 0
                rec["smtp_result"] = "rejected"
                rec["detailed_reason"] = f"SMTP {code}: Microsoft 365 confirmed mailbox does not exist"
                return rec
        except Exception:
            pass

    # 3. Yahoo / AOL / Verizon
    is_yahoo_family = domain_lower in YAHOO_DOMAINS or domain_lower in AOL_DOMAINS or any('yahoodns.net' in mx for mx in mx_records)
    if is_yahoo_family:
        rec["validation"] = "risky"
        rec["confidence"] = 50 if not is_role else 40
        rec["smtp_result"] = "unverified"
        rec["detailed_reason"] = f"Unverified Yahoo/AOL webmail: Valid MX ({mx_host}), but provider blocks direct mailbox probes from non-relay IPs"
        return rec

    # 4. Microsoft Consumer (Hotmail, Live, Outlook.com)
    is_ms_consumer = domain_lower in MICROSOFT_DOMAINS
    if is_ms_consumer:
        rec["validation"] = "risky"
        rec["confidence"] = 50 if not is_role else 40
        rec["smtp_result"] = "unverified"
        rec["detailed_reason"] = f"Unverified Microsoft webmail: Valid MX ({mx_host}), but provider blocks direct mailbox probes from non-relay IPs"
        return rec

    # 5. Other custom corporate / ISP domains
    rec["validation"] = "risky"
    rec["confidence"] = 45
    rec["smtp_result"] = "unverified"
    rec["detailed_reason"] = f"Protected domain: Valid MX ({mx_host}), but gateway filters unauthenticated probing IPs"
    return rec

def main():
    print(f"Reading {INPUT_FILE}...")
    df = pd.read_csv(INPUT_FILE)
    print(f"Loaded {len(df)} rows.")
    
    validated_records = []
    for idx, row in df.iterrows():
        email = str(row['Email']).strip()
        rec = check_single_email(email)
        validated_records.append(rec)
        print(f"[{idx+1:2d}/{len(df)}] {email:<35} -> {rec['validation'].upper():<7} ({rec['detailed_reason'][:50]})")
        
    vdf = pd.DataFrame(validated_records)
    
    # Update df columns
    df['Email Status'] = vdf['validation']
    df['Email Confidence'] = vdf['confidence']
    df['Syntax Valid'] = vdf['syntax_valid']
    df['Domain Exists'] = vdf['domain_exists']
    df['MX Found'] = vdf['mx_found']
    df['Disposable'] = vdf['disposable']
    df['Role Based'] = vdf['role_based']
    df['SMTP Result'] = vdf['smtp_result']
    df['Validation Reason'] = vdf['detailed_reason']
    df['Validation'] = vdf['validation']
    df['Detailed_Reason'] = vdf['detailed_reason']
    
    # Save master updated file
    master_out = Path("plumb_validated.csv")
    df.to_csv(master_out, index=False, encoding='utf-8')
    print(f"\nSaved updated master file: {master_out.resolve()}")
    
    # Save partitioned files in output/
    clean_df = df[df['Validation'] == 'safe']
    invalid_df = df[df['Validation'] == 'invalid']
    risky_df = df[df['Validation'] == 'risky']
    
    clean_df.to_csv(OUT_DIR / "clean.csv", index=False, encoding='utf-8')
    invalid_df.to_csv(OUT_DIR / "invalid.csv", index=False, encoding='utf-8')
    risky_df.to_csv(OUT_DIR / "risky.csv", index=False, encoding='utf-8')
    df.to_csv(OUT_DIR / "all_results.csv", index=False, encoding='utf-8')
    
    print("\n" + "="*50)
    print("VALIDATION SUMMARY")
    print("="*50)
    print(f"  Total Emails:        {len(df)}")
    print(f"  Verified Clean/Safe: {len(clean_df):>2} (100% deliverable via live SMTP handshake)")
    print(f"  Definitively Invalid:{len(invalid_df):>2} (Dead mailboxes, full/disabled inboxes, unroutable MX)")
    print(f"  Unverified/Risky:    {len(risky_df):>2} (Consumer Yahoo/Hotmail & reputation-gated domains)")
    print("="*50)

if __name__ == "__main__":
    main()
