# VERIFY360 — Python Flask Backend

SQLite database + Admin Panel to paste Excel data + full scan API.

---

## Folder Structure

```
verify360-flask/
├── app.py                  ← Flask app (run this)
├── requirements.txt        ← Python dependencies
├── verify360.db            ← SQLite DB (auto-created on first run)
└── templates/
    └── admin.html          ← Admin panel UI
```

---

## Setup (3 steps)

### 1 — Install Python 3.10+
Download from https://python.org if not already installed.

### 2 — Install dependencies
```bash
cd verify360-flask
pip install -r requirements.txt
```

### 3 — Run the server
```bash
python app.py
```

Open your browser at:
- **Admin Panel** → http://localhost:5000/admin
- **Frontend**    → your existing index.html (change BASE_URL to port 5000)

---

## Connecting your VERIFY360 frontend

In your `script.js`, change:
```js
const BASE_URL = "http://localhost:3000";
```
to:
```js
const BASE_URL = "http://localhost:5000";
```

That's it — all API routes are identical.

---

## How to paste Excel data

1. Open your Excel file
2. Make sure columns are in this order:
   | Value | Type | Description | Source |
   |-------|------|-------------|--------|
   | 9999999999 | Phone | Fake KYC call | cybercell |
   | scam-loans.tk | Website | Fake loan site | manual |
   | @fake_giveaway | Instagram | Fake prize account | |

3. Select your rows → **Ctrl+C**
4. Go to http://localhost:5000/admin
5. Click any cell in the **Value** column of the paste grid
6. Press **Ctrl+V** — all rows paste instantly
7. Click **💾 Save to Database**

> The Type column must be exactly one of: `Phone`, `WhatsApp`, `Website`, `Instagram`

---

## API Reference

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/scan` | Scan a number/URL/username |
| POST | `/api/report` | Report a scam (adds to DB) |
| GET  | `/api/live-feed` | Last 20 scans (masked) |
| GET  | `/api/stats` | Total counts |

### Scan Request
```json
POST /api/scan
{ "input": "9999999999", "type": "Phone" }
```

### Scan Response
```json
{
  "input": "9999999999",
  "type": "Phone",
  "threat": true,
  "risk_level": "HIGH",
  "score": 100,
  "reasons": ["Repeated digits", "Found in scam database (3 reports)"]
}
```

---

## Detection Logic

| Type | What is checked |
|------|----------------|
| Phone | Format, repeated/sequential digits, premium prefixes, DB lookup |
| Website | HTTPS, IP URLs, free TLDs (.tk .ml .ga), typosquatting, keyword scan |
| WhatsApp | Phone checks + wa.me link analysis |
| Instagram | Format, impersonation signals, digit flooding, DB lookup |

All types additionally check against your **known_scams** table.
