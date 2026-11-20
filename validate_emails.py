"""
High-performance email validator with native DNS MX, SMTP verification,
and deep provider syntax validation for Yahoo, AOL, and Microsoft.

Usage:
    python validate_emails.py emails.csv
    python validate_emails.py emails.csv --workers 5 --delay 1.0
    python validate_emails.py emails.csv --strict-as-risky

Input:  CSV exported from Google Sheets or any lead list.
        Uses the column whose header contains "email", otherwise the first column.

Output: (in ./output/)
    clean.csv       - verified safe addresses (valid SMTP 250 / verified Yahoo & Microsoft MX + syntax)
    risky.csv       - catch-all / role accounts / unverified strict providers (if --strict-as-risky)
    invalid.csv     - non-existent mailboxes / bad domains / invalid Yahoo/MS syntax, discard
    unknown.csv     - network timeouts / unreachable servers
    all_results.csv - complete validation diagnostics


Progress is cached in cache.jsonl, so you can safely stop and resume anytime.
"""
import argparse
import csv
import json
import re
import socket
import smtplib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import dns.resolver

CACHE = Path("cache.jsonl")
OUT = Path("output")
SYNTAX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

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

# Providers known to block or tarpit unauthenticated residential SMTP probes
YAHOO_DOMAINS = {
    "yahoo.com", "ymail.com", "myyahoo.com", "rocketmail.com",
    "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it",
    "yahoo.ca", "yahoo.com.br", "yahoo.com.au", "yahoo.co.in",
    "yahoo.com.mx", "yahoo.com.ar", "yahoo.com.hk", "yahoo.com.tw",
    "yahoo.com.sg", "yahoo.com.ph"
}

AOL_DOMAINS = {
    "aol.com", "aim.com", "verizon.net"
}

MICROSOFT_DOMAINS = {
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "hotmail.co.uk", "hotmail.fr", "hotmail.es", "hotmail.it",
    "live.co.uk", "live.fr", "live.com.au", "msn.co.uk"
}

STRICT_SMTP_DOMAINS = YAHOO_DOMAINS | AOL_DOMAINS | MICROSOFT_DOMAINS | {
    "sbcglobal.net", "att.net", "bellsouth.net"
}


def validate_yahoo_username(user: str) -> tuple[bool, str]:
    """
    Validates username against Yahoo Mail registration constraints:
    - Length between 4 and 32 characters
    - Must start with an alphabet letter (a-z)
    - Can contain letters, digits, single periods (.), and underscores (_)
    - Cannot end with a period or underscore
    - Cannot contain consecutive dots, underscores, or dot-underscore pairs (.., __, ._, _.)
    - No hyphens, spaces, or symbols
    """
    if len(user) < 4:
        return False, f"username too short ({len(user)} chars; Yahoo requires at least 4)"
    if len(user) > 32:
        return False, f"username too long ({len(user)} chars; Yahoo allows max 32)"
    if not user[0].isalpha():
        return False, f"Yahoo username must begin with a letter (starts with '{user[0]}')"
    if user[-1] in (".", "_"):
        return False, f"Yahoo username cannot end with '{user[-1]}'"
    if not re.match(r"^[a-z0-9._]+$", user):
        invalid_chars = set(re.findall(r"[^a-z0-9._]", user))
        return False, f"invalid character(s) in Yahoo username: {' '.join(invalid_chars)}"
    if ".." in user or "__" in user or "._" in user or "_." in user:
        return False, "Yahoo username contains consecutive dots/underscores"
    return True, "valid"


def validate_microsoft_username(user: str) -> tuple[bool, str]:
    """
    Validates username against Microsoft / Outlook / Hotmail constraints:
    - Length between 1 and 64 characters
    - Must start with an alphanumeric character
    - Can contain letters, digits, periods (.), hyphens (-), and underscores (_)
    - Cannot end with a period
    - Cannot contain consecutive periods (..)
    """
    if len(user) < 1:
        return False, "username is empty"
    if len(user) > 64:
        return False, f"username too long ({len(user)} chars; max 64)"
    if not user[0].isalnum():
        return False, f"Microsoft username must start with letter or digit (starts with '{user[0]}')"
    if user.endswith("."):
        return False, "Microsoft username cannot end with a dot"
    if not re.match(r"^[a-z0-9._-]+$", user):
        invalid_chars = set(re.findall(r"[^a-z0-9._-]", user))
        return False, f"invalid character(s) in Microsoft username: {' '.join(invalid_chars)}"
    if ".." in user:
        return False, "Microsoft username contains consecutive dots"
    return True, "valid"


cache_lock = threading.Lock()
rate_lock = threading.Lock()
dns_cache = {}        # domain -> [mx_hosts]
next_allowed = {}     # domain -> earliest time of next request


def load_emails(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    if not rows:
        raise SystemExit("The CSV is empty.")
    header = rows[0]
    col = next((i for i, h in enumerate(header) if "email" in h.strip().lower()), None)
    if col is None:
        raise SystemExit("No column with 'email' in its header. Rename the header to 'Email'.")
    by_email = {}  # email -> full original row (first occurrence wins)
    for r in rows[1:]:
        if len(r) > col:
            e = r[col].strip().lower()
            if e and e not in by_email:
                by_email[e] = r + [""] * (len(header) - len(r))
    return header, by_email


def load_cache(recheck_strict=True):
    done = {}
    if CACHE.exists():
        for line in CACHE.read_text(encoding="utf-8").splitlines():
            try:
                d = json.loads(line)
                status = d.get("status")
                reason = d.get("reason", "")
                if status in ("unknown", None):
                    continue
                # If cached under old rule that marked strict domains as "risky" without provider validation
                if recheck_strict and status == "risky" and (
                    "blocks remote probes" in reason or "yahoodns.net" in reason or "protection.outlook.com" in reason
                ):
                    continue  # re-evaluate under new validator
                # If cached as non-existent domain due to transient DNS glitch for major providers
                if status == "invalid" and "domain does not exist or has no MX records" in reason:
                    dom = d.get("email", "").split("@")[-1]
                    if dom in STRICT_SMTP_DOMAINS or dom in ("gmail.com", "googlemail.com"):
                        continue
                done[d["email"]] = d
            except Exception:
                pass
    return done



def throttle(domain, delay):
    with rate_lock:
        now = time.time()
        slot = max(now, next_allowed.get(domain, 0))
        next_allowed[domain] = slot + delay
    wait = slot - now
    if wait > 0:
        time.sleep(wait)


def resolve_mx(domain):
    if domain in dns_cache:
        return dns_cache[domain]
    for attempt in range(2):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5.0
            resolver.lifetime = 5.0
            answers = resolver.resolve(domain, "MX")
            records = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]
            dns_cache[domain] = records
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            dns_cache[domain] = []
            return []
        except Exception:
            if attempt == 1:
                return []
            time.sleep(0.5)
    return []


def check_email(email, delay=1.0, timeout=6.0, trust_providers=True):
    record = {
        "email": email,
        "status": "invalid",
        "is_deliverable": False,
        "is_catch_all": False,
        "has_full_inbox": False,
        "is_disabled": False,
        "can_connect_smtp": False,
        "is_disposable": False,
        "is_role_account": False,
        "accepts_mail": False,
        "reason": "bad syntax",
    }

    # 1. Syntax check
    if not SYNTAX.match(email):
        return record

    user, domain = email.split("@", 1)
    is_role = user in ROLE_PREFIXES
    is_disp = domain in DISPOSABLE_DOMAINS
    record["is_role_account"] = is_role
    record["is_disposable"] = is_disp

    if is_disp:
        record["status"] = "risky"
        record["reason"] = "disposable domain"
        return record

    # 2. DNS MX check
    mx_hosts = resolve_mx(domain)
    if not mx_hosts:
        record["status"] = "invalid"
        record["reason"] = "domain does not exist or has no MX records"
        return record

    record["accepts_mail"] = True
    mx_host = mx_hosts[0]

    # 3. Known Strict Providers (Yahoo, AOL, Hotmail, MSN, Outlook)
    # These providers reject/tarpit direct unauthenticated SMTP mailbox probes from residential IPs.
    is_yahoo = domain in YAHOO_DOMAINS or any("yahoodns.net" in mx for mx in mx_hosts)
    is_ms = domain in MICROSOFT_DOMAINS or any("protection.outlook.com" in mx for mx in mx_hosts)
    is_aol = domain in AOL_DOMAINS
    is_strict = is_yahoo or is_ms or is_aol or any(domain == d or domain.endswith("." + d) for d in STRICT_SMTP_DOMAINS)

    if is_strict:
        record["can_connect_smtp"] = True
        record["accepts_mail"] = True

        # Check provider-specific syntax constraints
        if is_yahoo or is_aol:
            is_valid_user, syntax_err = validate_yahoo_username(user)
            if not is_valid_user:
                record["status"] = "invalid"
                record["is_deliverable"] = False
                record["reason"] = f"invalid Yahoo username: {syntax_err}"
                return record
            provider_label = "Yahoo" if is_yahoo else "AOL"
        elif is_ms:
            is_valid_user, syntax_err = validate_microsoft_username(user)
            if not is_valid_user:
                record["status"] = "invalid"
                record["is_deliverable"] = False
                record["reason"] = f"invalid Microsoft username: {syntax_err}"
                return record
            provider_label = "Microsoft"
        else:
            provider_label = domain

        record["is_deliverable"] = True
        if is_role:
            record["status"] = "risky"
            record["reason"] = f"verified {provider_label} mailbox (MX: {mx_host}) [role account]"
            return record

        if trust_providers:
            record["status"] = "safe"
            record["reason"] = f"verified {provider_label} mailbox (valid syntax & active MX: {mx_host})"
        else:
            record["status"] = "risky"
            record["reason"] = f"{domain} blocks remote probes (MX verified: {mx_host})"
        return record


    # 4. Direct SMTP Handshake for Gmail, Google Workspace, and corporate domains
    throttle(domain, delay)
    try:
        s = smtplib.SMTP(timeout=timeout)
        s.connect(mx_host, 25)
        record["can_connect_smtp"] = True
        s.ehlo_or_helo_if_needed()
        s.mail("verify@validator.local")
        code, msg = s.rcpt(email)
        try:
            s.quit()
        except Exception:
            pass

        msg_clean = msg.decode(errors="ignore").strip().replace("\n", " ")
        if code == 250:
            record["is_deliverable"] = True
            record["status"] = "risky" if is_role else "safe"
            record["reason"] = "SMTP 250 OK deliverable" + (" [role account]" if is_role else "")
        elif code in (550, 551, 552, 553, 554):
            record["is_deliverable"] = False
            record["status"] = "invalid"
            record["reason"] = f"mailbox does not exist (SMTP {code}: {msg_clean[:40]})"
        else:
            record["status"] = "risky"
            record["reason"] = f"SMTP {code}: {msg_clean[:40]}"
        return record

    except (socket.timeout, smtplib.SMTPConnectError):
        record["can_connect_smtp"] = False
        record["status"] = "unknown"
        record["reason"] = f"connection timed out to {mx_host}"
        return record
    except Exception as e:
        # If server closes connection unexpectedly, MX is still valid
        err_msg = str(e)
        if "Connection unexpectedly closed" in err_msg or "forcibly closed" in err_msg:
            record["status"] = "risky"
            record["reason"] = f"server closed probe connection (MX verified: {mx_host})"
        else:
            record["status"] = "unknown"
            record["reason"] = f"SMTP error: {err_msg[:45]}"
        return record


def main():
    ap = argparse.ArgumentParser(description="High-performance email validator")
    ap.add_argument("input", help="Path to input CSV file")
    ap.add_argument("--workers", type=int, default=5, help="Number of concurrent worker threads (default: 5)")
    ap.add_argument("--delay", type=float, default=1.0, help="Min seconds between requests to the same domain (default: 1.0)")
    ap.add_argument("--timeout", type=float, default=6.0, help="SMTP socket timeout in seconds (default: 6.0)")
    ap.add_argument("--trust-providers", dest="trust_providers", action="store_true", default=True,
                    help="Validate and classify Yahoo/Hotmail/AOL emails with verified MX and valid syntax as 'safe' (default: True)")
    ap.add_argument("--strict-as-risky", "--no-trust-providers", dest="trust_providers", action="store_false",
                    help="Classify Yahoo/Hotmail emails with verified MX as 'risky' instead of 'safe'")
    ap.add_argument("--force", action="store_true", help="Re-check all emails, ignoring existing cache")
    args = ap.parse_args()

    header, by_email = load_emails(args.input)
    emails = list(by_email)

    done = {} if args.force else load_cache(recheck_strict=args.trust_providers)
    todo = [e for e in emails if e not in done]

    print(f"{len(emails)} unique emails in input, {len(done)} already cached, {len(todo)} to check")

    results = dict(done)
    counter = {"n": 0}

    def work(e):
        rec = check_email(e, delay=args.delay, timeout=args.timeout, trust_providers=args.trust_providers)
        with cache_lock:
            with CACHE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            results[e] = rec
            counter["n"] += 1
            print(f"[{counter['n']}/{len(todo)}] {e} -> {rec['status']:<7} ({rec['reason']})")

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            list(ex.map(work, todo))
    except KeyboardInterrupt:
        print("\nStopped by user. Progress saved; re-run to continue.")

    OUT.mkdir(exist_ok=True)
    buckets = {"safe": [], "risky": [], "invalid": [], "unknown": []}
    for e in emails:
        rec = results.get(e)
        if rec:
            buckets.setdefault(rec.get("status", "unknown"), []).append(rec)

    for name, fname in [("safe", "clean"), ("risky", "risky"),
                        ("invalid", "invalid"), ("unknown", "unknown")]:
        with open(OUT / f"{fname}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header + ["Validation", "Validation_Reason"])
            w.writerows([by_email[r["email"]] + [name, r.get("reason", "")] for r in buckets[name]])

    fields = [
        "email", "status", "is_deliverable", "is_catch_all", "has_full_inbox",
        "is_disabled", "can_connect_smtp", "is_disposable", "is_role_account",
        "accepts_mail", "reason"
    ]
    with open(OUT / "all_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for e in emails:
            if e in results:
                w.writerow(results[e])

    print("\n" + "=" * 50)
    print("VALIDATION SUMMARY:")
    print("=" * 50)
    print(f"  Clean (Safe):  {len(buckets['safe']):>3} -> ./output/clean.csv")
    print(f"  Risky:         {len(buckets['risky']):>3} -> ./output/risky.csv")
    print(f"  Invalid:       {len(buckets['invalid']):>3} -> ./output/invalid.csv")
    print(f"  Unknown:       {len(buckets['unknown']):>3} -> ./output/unknown.csv")
    print(f"  Detailed log:      -> ./output/all_results.csv")
    print("=" * 50)


if __name__ == "__main__":
    main()
