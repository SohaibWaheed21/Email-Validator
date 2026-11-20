from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import pandas as pd
import os

df = pd.read_csv("output/risky.csv")
yahoo_mask = df["Email"].str.contains(r"@(?:yahoo|ymail|aol|verizon)\.(?:com|net)", case=False, na=False)
yahoo_df = df[yahoo_mask].copy()

print(f"Total Yahoo/AOL leads found in risky.csv: {len(yahoo_df)}")

options = Options()
options.add_argument("--headless=new")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--window-size=1280,800")
options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

driver = webdriver.Chrome(options=options)

results = []

try:
    for idx, row in yahoo_df.iterrows():
        email = row["Email"]
        biz = row["Business Name"]
        print(f"[{len(results)+1}/{len(yahoo_df)}] Checking: {email} ({biz})")
        
        status = "UNKNOWN"
        reason = ""
        
        try:
            driver.get("https://login.yahoo.com/")
            username_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, "username"))
            )
            username_field.clear()
            username_field.send_keys(email)
            time.sleep(1)
            username_field.send_keys(Keys.ENTER)
            
            time.sleep(3.5)
            
            current_url = driver.current_url
            page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            
            if "we don't recognize" in page_text or "sorry, we don't" in page_text or "doesn't exist" in page_text:
                status = "INVALID"
                reason = "Yahoo account does not exist / purged due to inactivity"
            elif "/account/challenge" in current_url or "password" in page_text or "/password" in current_url or "yak-code" in current_url:
                status = "DELIVERABLE"
                reason = "Yahoo account exists and active (prompted challenge/password)"
            elif "too many attempts" in page_text or "temporarily blocked" in page_text:
                status = "RATE_LIMITED"
                reason = "Yahoo edge rate limit reached"
            else:
                status = "UNKNOWN"
                reason = f"Unhandled page state (URL: {current_url[:40]})"
                
        except Exception as e:
            status = "ERROR"
            reason = str(e)
            
        print(f"  -> {status}: {reason}")
        results.append({
            "Business Name": biz,
            "Email": email,
            "Yahoo_Status": status,
            "Yahoo_Reason": reason
        })
        
        if status == "RATE_LIMITED":
            print("Rate limit detected, stopping early to preserve IP.")
            break
            
        time.sleep(2) # polite pacing
        
finally:
    driver.quit()

res_df = pd.DataFrame(results)
res_df.to_csv("output/yahoo_verification_results.csv", index=False)
print("\n" + "="*50)
print("YAHOO VERIFICATION BATCH SUMMARY:")
print(res_df["Yahoo_Status"].value_counts())
print("="*50)
