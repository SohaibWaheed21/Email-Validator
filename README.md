# 📧 Email Validator & Verification Suite

A multi-tier email validation engine designed to maximize email deliverability, eliminate bounce rates, and detect invalid or inactive mailboxes across major email service providers (Google, Microsoft, Yahoo/AOL, and custom domains).

---

## 🚀 Key Features

- **Multi-Tier Verification Pipeline**:
  - **Tier 1 (Syntax & DNS MX)**: Validates RFC format and queries live DNS MX records.
  - **Tier 2 (Google / Workspace SMTP)**: Direct SMTP `RCPT TO` handshake over IPv6/IPv4 to verify mailbox existence without sending emails.
  - **Tier 3 (Microsoft Live Directory API)**: Live enumeration endpoint (`GetCredentialType`) to verify Outlook, Hotmail, Live, and MSN accounts.
  - **Tier 4 (Yahoo / AOL Automated Web Check)**: Automated headless Chrome evaluation to accurately check Yahoo, Ymail, AOL, and Verizon mailboxes that block unauthenticated residential SMTP.
  - **Tier 5 (Custom & Enterprise Domains)**: Verifies MX reachability and flags catch-all/firewalled domains appropriately.
- **Smart Column Detection**: Automatically detects email columns regardless of case (e.g., `Email`, `email`, `Business Email`).
- **Clean Output Partitioning**: Automatically divides results into `clean.csv`, `invalid.csv`, `risky.csv`, and a complete master log.
- **CRM Ready**: Appends a configurable `Status` column (e.g., `"sent"`, `"verified"`) to clean lists for direct import into outreach tools or CRMs.

---

## 📁 Repository Structure

| File / Directory | Description |
| :--- | :--- |
| **`validate_all.py`** | **Primary turnkey script.** Runs the complete multi-tier validation pipeline on any CSV. |
| **`validate_emails.py`** | High-performance multi-threaded SMTP & DNS validator with persistent JSONL caching (`cache.jsonl`). |
| **`verify_microsoft.py`** | Standalone verification tool for Microsoft accounts (`@hotmail`, `@outlook`, `@live`, `@msn`). |
| **`verify_yahoo_selenium.py`** | Standalone headless Selenium verification tool for Yahoo & AOL domains. |
| **`verify_with_api.py`** | Verification fallback using third-party APIs (Hunter.io, ZeroBounce, Debounce). |
| **`requirements.txt`** | Python dependencies list. |
| **`.gitignore`** | Ignores cache files, virtual environments, output folders, and system artifacts. |

---

## 🛠️ Prerequisites & Installation

### 1. Requirements
- **Python**: 3.10 or higher.
- **Google Chrome**: Installed on the host system (required for Selenium-based Yahoo verification).

### 2. Clone the Repository
```bash
git clone https://github.com/SohaibWaheed21/Email-Validator.git
cd Email-Validator
```

### 3. Set Up a Virtual Environment (Recommended)

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**On Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 How to Run

### Option 1: Turnkey Multi-Tier Validation (`validate_all.py`) — Recommended

This script executes all verification tiers sequentially, handles provider routing, and creates timestamped output folders.

#### Basic Usage:
```bash
python validate_all.py your_emails.csv
```

#### Specify a Custom Output Directory:
```bash
python validate_all.py your_emails.csv --output-dir my_validated_results
```

#### Custom Clean Status Tag:
By default, `clean.csv` includes a column `Status = "sent"`. You can customize this tag:
```bash
python validate_all.py your_emails.csv --clean-status "verified"
```

---

### Option 2: High-Performance Multi-Threaded Validator (`validate_emails.py`)

Designed for large datasets with concurrent workers, throttling, and resume support.

```bash
# Standard run
python validate_emails.py emails.csv

# Multi-threaded with custom delay and workers
python validate_emails.py emails.csv --workers 5 --delay 1.0

# Treat strict/unverified webmail providers as risky
python validate_emails.py emails.csv --strict-as-risky
```

> **Resume Support**: `validate_emails.py` saves progress in `cache.jsonl`. If interrupted, rerun the command to continue where it stopped.

---

### Option 3: Standalone & Verification Tools

#### 1. Microsoft Live Verification (`verify_microsoft.py`)
Reads from `output/risky.csv` and verifies Microsoft domains:
```bash
python verify_microsoft.py
```

#### 2. Yahoo / AOL Selenium Verification (`verify_yahoo_selenium.py`)
Runs automated headless Chrome checks against Yahoo/AOL login endpoints:
```bash
python verify_yahoo_selenium.py
```

#### 3. Third-Party API Verification (`verify_with_api.py`)
Verify remaining ambiguous addresses using third-party verification APIs:
```bash
# Using Hunter.io
python verify_with_api.py --provider hunter --key YOUR_API_KEY

# Using ZeroBounce
python verify_with_api.py --provider zerobounce --key YOUR_API_KEY

# Using Debounce
python verify_with_api.py --provider debounce --key YOUR_API_KEY
```

---

## 📊 Output Formats

Validation runs generate a dedicated folder containing the partitioned results:

| Output File | Description | Recommended Action |
| :--- | :--- | :--- |
| **`clean.csv`** | Verified active mailboxes with passing syntax and DNS MX. | Safe to send campaigns. |
| **`invalid.csv`** | Non-existent mailboxes, bad syntax, or dead domains. | Discard / remove from list. |
| **`risky.csv`** | Catch-all domains, unverified custom MX, or rate-limited checks. | Manual review or warmup sending. |
| **`<filename>_validated.csv`** | Complete dataset containing status codes and diagnostic notes (`Email Status`, `Email Confidence`, `SMTP Result`, `Detailed_Reason`). | Audit and troubleshooting. |

---

## ⚙️ How the Multi-Tier Engine Works

```
                     Input CSV
                         │
                         ▼
             [ Tier 1: Syntax & DNS MX ]
                 │                │
           (Invalid Syntax/MX) (Valid MX)
                 │                │
                 ▼                ▼
            invalid.csv    Provider Routing
                         ┌────────┼────────┬────────┐
                         ▼        ▼        ▼        ▼
                      Google  Microsoft  Yahoo    Custom
                         │        │        │        │
                     [SMTP 250] [LiveAPI][Selenium] [MX Check]
                         └────────┼────────┴────────┘
                                  ▼
                    Partition & Export Results:
               clean.csv  |  risky.csv  |  invalid.csv
```

---

## ⚠️ Notes & Troubleshooting

- **ISP Port 25 Filtering**: Some residential internet service providers block outbound traffic on port 25. If SMTP handshakes time out, run the script on a VPS/cloud server (or use `verify_with_api.py` for API fallbacks).
- **Headless Chrome**: `verify_yahoo_selenium.py` and `validate_all.py` use headless Chrome. Ensure Google Chrome is installed on the machine. Selenium 4 automatically configures the matching driver.
- **Rate Limits**: If validating tens of thousands of emails in a single run, add delays or break inputs into batches to avoid provider IP rate limits.

---

## 📄 License
This project is open-source and available under the [MIT License](LICENSE).
