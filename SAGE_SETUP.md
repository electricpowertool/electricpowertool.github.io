# Automated Daily Sage Accounting Sync Setup

This repository includes a daily GitHub Actions workflow ([`.github/workflows/sync-sage.yml`](.github/workflows/sync-sage.yml)) that pulls live active stock items from **Sage Business Cloud Accounting (Ireland, API v3.1)** every morning at **07:00 UTC** (7:00 AM GMT / 8:00 AM IST), rebuilds `index.html`, and publishes it automatically to GitHub Pages.

- Uses **read-only** (`readonly`) Sage OAuth access — it can never edit your books.
- Automatically saves Sage's rotated 31-day refresh token after every run so it stays connected indefinitely.
- Keeps prices encrypted in `index.html` and never commits raw CSVs or plaintext prices.

---

## One-Time Setup

### Step 1 — Create a Sage App (already done)
On https://developerselfservice.sageone.com/, your app should include these **Callback URLs**:
```text
http://localhost:8080/callback
https://oauth.pstmn.io/v1/browser-callback
```
Keep your **Client ID** and **Client Secret** handy.

---

### Step 2 — Create a repo-scoped GitHub Token (`GH_SECRETS_PAT`)
Sage rotates its refresh token every time it is used. GitHub Actions' default token cannot update repository secrets, so we create a minimal token scoped **only** to this repository's secrets:

1. Open https://github.com/settings/personal-access-tokens/new
2. **Token name:** `EPT Sage Refresh Token Updater`
3. **Resource owner:** `electricpowertool`
4. **Expiration:** Custom / 1 year (set a calendar reminder to renew once a year)
5. **Repository access:** **Only select repositories** → select `electricpowertool/electricpowertool.github.io`
6. **Permissions → Repository permissions:**
   - **Secrets:** `Read and write`
   - *(Leave all other permissions on No access)*
7. Click **Generate token** and copy the token (`github_pat_...`).

---

### Step 3 — Authorize Sage Once to Get `SAGE_REFRESH_TOKEN`

#### Option A — Using Python (fastest, ~30 seconds)
On your computer, download/clone this repo (or just `scripts/sage_auth.py`) and run:

```bash
python3 scripts/sage_auth.py
```

1. Enter your **Sage Client ID** and **Sage Client Secret**.
2. Your browser will open Sage Ireland — sign in with your **Sage Accounting company login** (not your developer login) and click **Allow**.
3. The script catches the redirect automatically and prints your `SAGE_REFRESH_TOKEN` (and `SAGE_BUSINESS_ID`).

#### Option B — Using Postman (if you don't have Python installed)
1. In Postman, open a new request → **Authorization** tab → **Type: OAuth 2.0**.
2. Configure New Token:
   - **Grant Type:** `Authorization Code`
   - **Callback URL:** `https://oauth.pstmn.io/v1/browser-callback` (or check *Authorize using browser*)
   - **Auth URL:** `https://www.sageone.com/oauth2/auth/central?filter=apiv3.1&country=ie`
   - **Access Token URL:** `https://oauth.accounting.sage.com/token`
   - **Client ID / Client Secret:** from Step 1
   - **Scope:** `readonly`
   - **Client Authentication:** `Send client credentials in body`
3. Click **Get New Access Token**, sign in to Sage Ireland, click **Allow**, and copy the **`refresh_token`** from the token details.

---

### Step 4 — Add Secrets to GitHub
Open **https://github.com/electricpowertool/electricpowertool.github.io/settings/secrets/actions** and add these **Repository secrets**:

| Secret name | Value |
|---|---|
| `SAGE_CLIENT_ID` | Client ID from Sage App Registry |
| `SAGE_CLIENT_SECRET` | Client Secret from Sage App Registry |
| `SAGE_REFRESH_TOKEN` | Refresh token from Step 3 |
| `GH_SECRETS_PAT` | Fine-grained GitHub PAT from Step 2 |
| `SAGE_BUSINESS_ID` | *(Optional)* Business ID from Step 3 — only needed if your Sage login has multiple companies |

---

### Step 5 — Run Your First Sync!
1. Open **https://github.com/electricpowertool/electricpowertool.github.io/actions/workflows/sync-sage.yml**
2. Click **Run workflow** → **Run workflow**.
3. Within ~15 seconds, the action will pull all live stock items from Sage, rotate and save the new refresh token, and publish any changes to `https://electricpowertool.github.io/`.

---

## Managing Categories for Brand-New Products
Sage's v3.1 `stock_items` API does not expose UI product categories, so `categories.json` maps item codes to their category (pre-populated from your current Sage export). When you add a brand-new item in Sage, it will still appear in the catalogue automatically under **Other** (and be listed in the GitHub Actions log), and you can optionally add its `"ITEM_CODE": "Category"` entry to `categories.json`.
