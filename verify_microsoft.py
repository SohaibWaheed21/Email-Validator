import requests
import re
import json
import time
import pandas as pd

df = pd.read_csv("output/risky.csv")
ms_mask = df["Email"].str.contains(r"@(?:hotmail|live|msn|outlook)\.com", case=False, na=False)
ms_df = df[ms_mask].copy()

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

def get_session_and_token():
    s = requests.Session()
    r = s.get("https://login.live.com/", headers=headers, timeout=10)
    m = re.search(r'sFTTag["\']?\s*:\s*["\'].*?value=\\"([^\\"]+)\\"', r.text)
    if not m:
        m = re.search(r'value="([^"]+)"\s+name="PPFT"', r.text)
    token = m.group(1) if m else None
    return s, token

results = []
s, current_token = get_session_and_token()

for idx, row in ms_df.iterrows():
    email = row["Email"]
    success = False
    
    for attempt in range(2):
        if not current_token:
            s, current_token = get_session_and_token()
            
        payload = {
            "username": email,
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
            "flowToken": current_token
        }
        try:
            r = s.post("https://login.live.com/GetCredentialType.srf", headers=post_headers, json=payload, timeout=10)
            data = r.json()
            if_exists = data.get("IfExistsResult")
            
            # Update flowToken if provided in response
            if data.get("FlowToken"):
                current_token = data.get("FlowToken")
                
            if if_exists is not None:
                if if_exists == 0:
                    status = "DELIVERABLE"
                    reason = "Microsoft Live enumeration: Account exists (IfExistsResult=0)"
                elif if_exists == 1:
                    status = "INVALID"
                    reason = "Microsoft Live enumeration: Mailbox purged/does not exist (IfExistsResult=1)"
                else:
                    status = f"CODE_{if_exists}"
                    reason = f"Microsoft Live code {if_exists}"
                success = True
                break
            else:
                # Token might have expired, refresh on next attempt
                s, current_token = get_session_and_token()
                time.sleep(1)
        except Exception as e:
            s, current_token = get_session_and_token()
            time.sleep(1)
            
    if not success:
        status = "UNKNOWN"
        reason = "Flow token expired or blocked"
        
    print(f"{email:<35} -> {status} ({reason})")
    results.append({
        "Email": email,
        "MS_Status": status,
        "MS_Reason": reason
    })
    time.sleep(1)

res_df = pd.DataFrame(results)
res_df.to_csv("output/ms_verification_results.csv", index=False)
print("\n" + "="*50)
print("FINAL MICROSOFT ENUMERATION SUMMARY:")
print(res_df["MS_Status"].value_counts())
print("="*50)
