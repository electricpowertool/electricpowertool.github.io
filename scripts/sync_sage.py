#!/usr/bin/env python3
"""
Fetches live stock items from Sage Business Cloud Accounting API v3.1 (Ireland)
and rebuilds index.html using build.py.

Designed to run daily in GitHub Actions (zero third-party Python dependencies):
- Verifies GH_SECRETS_PAT before refreshing so a Sage refresh token is never burned
  without being able to persist the rotated token back to GitHub Secrets.
- Immediately rotates & saves SAGE_REFRESH_TOKEN after token refresh.
- Uses categories.json as fallback for item categories (since Sage's v3.1
  stock_items API does not expose UI categories).
- Uses a keyed HMAC fingerprint (.data-fingerprint) so index.html is only rebuilt
  and committed when product, stock, price, or template data actually changes.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from build import compute_fingerprint, normalize_number, render_catalog  # noqa: E402

TOKEN_URL = "https://oauth.accounting.sage.com/token"
API_BASE = "https://api.accounting.sage.com/v3.1"
USER_AGENT = "EPT-Catalogue-Sync/1.0"


def _http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = 30,
    max_retries: int = 4,
) -> tuple[dict, dict[str, str]]:
    req_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)

    for attempt in range(max_retries):
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return json.loads(body), resp_headers
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            retryable = exc.code in (429, 500, 502, 503, 504)
            if retryable and attempt < max_retries - 1:
                retry_after = exc.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt) * 2
                print(f"HTTP {exc.code} from {url}; retrying in {delay:.0f}s...", file=sys.stderr)
                time.sleep(delay)
                continue
            raise RuntimeError(f"HTTP {exc.code} from {url}: {err_body[:500]}") from exc
        except urllib.error.URLError as exc:
            if attempt < max_retries - 1:
                delay = (2 ** attempt) * 2
                print(f"Network error ({exc.reason}); retrying in {delay:.0f}s...", file=sys.stderr)
                time.sleep(delay)
                continue
            raise RuntimeError(f"Network error calling {url}: {exc.reason}") from exc

    raise RuntimeError(f"Exhausted retries calling {url}")


def verify_github_secret_access(repo: str, secrets_pat: str) -> None:
    """Confirm GH_SECRETS_PAT can update repo Actions secrets BEFORE touching Sage tokens."""
    env = os.environ.copy()
    env["GH_TOKEN"] = secrets_pat
    proc = subprocess.run(
        ["gh", "api", f"/repos/{repo}/actions/secrets/public-key"],
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "Pre-flight check failed: GH_SECRETS_PAT cannot access repository Actions secrets "
            f"for {repo}. Aborting BEFORE refreshing Sage token so your refresh token stays valid.\n"
            f"Details: {proc.stderr.strip()}"
        )


def save_github_secret(repo: str, secret_name: str, secret_value: str, secrets_pat: str) -> None:
    env = os.environ.copy()
    env["GH_TOKEN"] = secrets_pat
    proc = subprocess.run(
        ["gh", "secret", "set", secret_name, "--repo", repo],
        input=secret_value,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to save rotated {secret_name} to GitHub Secrets: {proc.stderr.strip()}")


class SageClient:
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        business_id: str = "",
        gh_repo: str = "",
        gh_secrets_pat: str = "",
        save_rotated_token: bool = True,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.business_id = business_id.strip()
        self.gh_repo = gh_repo
        self.gh_secrets_pat = gh_secrets_pat
        self.save_rotated_token = save_rotated_token
        self.access_token = ""
        self.token_obtained_at = 0.0

    def refresh(self) -> None:
        payload = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
            }
        ).encode("utf-8")

        data, _ = _http_json(
            TOKEN_URL,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=payload,
        )
        new_access = data.get("access_token")
        new_refresh = data.get("refresh_token")
        if not new_access or not new_refresh:
            raise RuntimeError("Sage token response missing access_token or refresh_token.")

        self.access_token = new_access
        self.refresh_token = new_refresh
        self.token_obtained_at = time.monotonic()

        # Persist immediately so the rotated token is never lost even if a later step fails.
        if self.save_rotated_token:
            save_github_secret(self.gh_repo, "SAGE_REFRESH_TOKEN", new_refresh, self.gh_secrets_pat)
            print("Refreshed Sage token and saved rotated SAGE_REFRESH_TOKEN to GitHub Secrets.")
        else:
            print("Refreshed Sage token (local mode — secret not saved to GitHub).")

    def _ensure_token(self) -> None:
        # Sage access tokens expire after 300 seconds; refresh proactively at 240 seconds.
        if not self.access_token or (time.monotonic() - self.token_obtained_at) > 240:
            self.refresh()

    def _resolve_business_id(self) -> str:
        """Validate SAGE_BUSINESS_ID against /businesses so a malformed secret cannot cause HTTP 500."""
        self._ensure_token()
        headers = {"Authorization": f"Bearer {self.access_token}"}
        try:
            data, _ = _http_json(f"{API_BASE}/businesses", headers=headers)
        except Exception as exc:  # noqa: BLE001
            print(f"Note: could not query /businesses ({exc}); continuing with configured business ID.")
            return self.business_id

        businesses = data.get("$items") or []
        valid_ids = {b.get("id", "").strip(): b.get("displayed_as", "") for b in businesses if b.get("id")}
        print(f"Sage account has {len(valid_ids)} accessible business(es).")

        candidate = self.business_id
        if candidate and ":" in candidate:
            # Handle accidental copy of "- Business Name: <id>" format.
            candidate = candidate.rsplit(":", 1)[-1].strip()

        if candidate and candidate in valid_ids:
            print(f"Using configured Sage business: {valid_ids[candidate]} ({candidate})")
            return candidate

        if candidate and candidate not in valid_ids:
            print(
                "Warning: SAGE_BUSINESS_ID did not match any business on this Sage account; "
                "falling back to lead business."
            )

        if len(valid_ids) == 1:
            only_id, only_name = next(iter(valid_ids.items()))
            print(f"Using Sage business: {only_name} ({only_id})")
            return only_id

        return ""

    def fetch_all_stock_items(self) -> list[dict]:
        resolved_business_id = self._resolve_business_id()

        query_variants = [
            "attributes=item_code,description,sales_prices,quantity_in_stock,barcode,active&items_per_page=100",
            "attributes=all&items_per_page=50",
        ]

        last_err: Exception | None = None
        for idx, query in enumerate(query_variants):
            try:
                return self._fetch_stock_items_with_query(query, resolved_business_id)
            except RuntimeError as exc:
                last_err = exc
                if idx < len(query_variants) - 1:
                    print(f"Query variant {idx + 1} failed ({exc}); trying fallback query...", file=sys.stderr)
                    continue
                raise

        assert last_err is not None
        raise last_err

    def _fetch_stock_items_with_query(self, query: str, business_id: str) -> list[dict]:
        items: list[dict] = []
        next_url: str | None = f"{API_BASE}/stock_items?{query}"
        logged_business = False
        page = 0

        while next_url:
            self._ensure_token()
            page += 1
            headers = {"Authorization": f"Bearer {self.access_token}"}
            if business_id:
                headers["X-Business"] = business_id

            data, resp_headers = _http_json(next_url, headers=headers)
            if not logged_business:
                biz = resp_headers.get("x-business")
                if biz:
                    print(f"Connected to Sage business ID: {biz}")
                logged_business = True

            batch = data.get("$items") or []
            items.extend(batch)
            total = data.get("$total")
            print(f"Fetched page {page}: {len(batch)} items ({len(items)}/{total or '?'})")

            nxt = data.get("$next")
            if not nxt:
                next_url = None
            elif nxt.startswith("http://") or nxt.startswith("https://"):
                next_url = nxt
            elif nxt.startswith("/v3.1/"):
                next_url = f"https://api.accounting.sage.com{nxt}"
            else:
                next_url = f"{API_BASE}{nxt if nxt.startswith('/') else '/' + nxt}"

        return items


def extract_sales_price(item: dict) -> int | float:
    prices = item.get("sales_prices") or []
    if not isinstance(prices, list) or not prices:
        return 0

    for entry in prices:
        name = (entry.get("price_name") or "").strip().lower()
        ptype = entry.get("product_sales_price_type") or {}
        type_name = (ptype.get("displayed_as") or "").strip().lower() if isinstance(ptype, dict) else ""
        if name == "sales price" or type_name == "sales price":
            return normalize_number(entry.get("price"))

    return normalize_number(prices[0].get("price"))


def extract_category(item: dict, code: str, category_map: dict[str, str]) -> str:
    raw_cat = item.get("category")
    if isinstance(raw_cat, dict):
        name = (raw_cat.get("displayed_as") or raw_cat.get("name") or "").strip()
        if name:
            return name
    elif isinstance(raw_cat, str) and raw_cat.strip():
        return raw_cat.strip()

    return category_map.get(code, "Other")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync stock from Sage Accounting Ireland and rebuild index.html.")
    parser.add_argument("--title", default=os.environ.get("CATALOG_TITLE") or "Electric Power Tool Co. Ltd.")
    parser.add_argument("--view-code", default=os.environ.get("CATALOG_VIEW_CODE") or "EPT100")
    parser.add_argument("--price-code", default=os.environ.get("CATALOG_PRICE_CODE") or "EPT749")
    parser.add_argument("--stock-code", default=os.environ.get("CATALOG_STOCK_CODE") or "EPT500")
    parser.add_argument("--order-code", default=os.environ.get("CATALOG_ORDER_CODE") or "EPT900")
    parser.add_argument("--out", default=str(ROOT / "index.html"))
    parser.add_argument("--force", action="store_true", help="Rebuild index.html even if data fingerprint is unchanged.")
    parser.add_argument(
        "--no-save-secret",
        action="store_true",
        help="Do not save rotated SAGE_REFRESH_TOKEN back to GitHub Secrets (for local testing only).",
    )
    args = parser.parse_args()

    client_id = (os.environ.get("SAGE_CLIENT_ID") or "").strip()
    client_secret = (os.environ.get("SAGE_CLIENT_SECRET") or "").strip()
    refresh_token = (os.environ.get("SAGE_REFRESH_TOKEN") or "").strip()
    business_id = (os.environ.get("SAGE_BUSINESS_ID") or "").strip()

    missing = [
        name
        for name, val in [
            ("SAGE_CLIENT_ID", client_id),
            ("SAGE_CLIENT_SECRET", client_secret),
            ("SAGE_REFRESH_TOKEN", refresh_token),
        ]
        if not val
    ]
    if missing:
        raise SystemExit(f"Missing required environment variable(s): {', '.join(missing)}")

    gh_repo = (os.environ.get("GITHUB_REPOSITORY") or "").strip()
    gh_secrets_pat = (os.environ.get("GH_SECRETS_PAT") or "").strip()
    save_secret = not args.no_save_secret

    if save_secret:
        if not gh_repo or not gh_secrets_pat:
            raise SystemExit(
                "Missing GITHUB_REPOSITORY or GH_SECRETS_PAT. "
                "Add GH_SECRETS_PAT (fine-grained PAT with Actions Secrets Read & Write) "
                "before running so the rotated Sage refresh token can be saved."
            )
        verify_github_secret_access(gh_repo, gh_secrets_pat)

    client = SageClient(
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
        business_id=business_id,
        gh_repo=gh_repo,
        gh_secrets_pat=gh_secrets_pat,
        save_rotated_token=save_secret,
    )

    raw_items = client.fetch_all_stock_items()

    categories_path = ROOT / "categories.json"
    category_map: dict[str, str] = {}
    if categories_path.exists():
        category_map = json.loads(categories_path.read_text(encoding="utf-8"))

    rows: list[tuple[str, str, str, str, int | float, int | float]] = []
    uncategorized: list[str] = []

    for item in raw_items:
        if item.get("active") is False:
            continue
        code = (item.get("item_code") or "").strip()
        desc = (item.get("description") or "").strip()
        if not code or not desc:
            continue

        category = extract_category(item, code, category_map)
        if category == "Other" and code not in category_map:
            uncategorized.append(code)

        barcode = (item.get("barcode") or "").strip()
        qty = normalize_number(item.get("quantity_in_stock"))
        price = extract_sales_price(item)
        rows.append((code, desc, category, barcode, qty, price))

    if not rows:
        raise SystemExit("Sage returned 0 active stock items — aborting to avoid emptying the catalogue.")

    # Deterministic order so pagination differences do not trigger spurious rebuilds.
    rows.sort(key=lambda r: (r[2].lower(), r[0].lower()))

    products = [[code, desc, category, barcode, qty] for code, desc, category, barcode, qty, _ in rows]
    prices = [price for *_, price in rows]

    template_path = ROOT / "template.html"
    output_path = Path(args.out)
    fingerprint_path = ROOT / ".data-fingerprint"

    template_text = template_path.read_text(encoding="utf-8")
    new_fingerprint = compute_fingerprint(
        products=products,
        prices=prices,
        template_text=template_text,
        title=args.title,
        view_code=args.view_code,
        price_code=args.price_code,
        stock_code=args.stock_code,
        order_code=args.order_code,
    )

    old_fingerprint = fingerprint_path.read_text(encoding="utf-8").strip() if fingerprint_path.exists() else ""
    in_stock_count = sum(1 for p in products if p[4] > 0)
    print(f"Processed {len(products)} active stock items ({in_stock_count} in stock).")

    if uncategorized:
        sample = ", ".join(sorted(uncategorized)[:15])
        extra = f" (+{len(uncategorized) - 15} more)" if len(uncategorized) > 15 else ""
        print(f"Note: {len(uncategorized)} item(s) defaulted to 'Other' category: {sample}{extra}")

    if not args.force and old_fingerprint == new_fingerprint and output_path.exists():
        print("No catalogue changes detected — skipping index.html rebuild.")
        return

    count = render_catalog(
        products=products,
        prices=prices,
        template_path=template_path,
        output_path=output_path,
        title=args.title,
        view_code=args.view_code,
        price_code=args.price_code,
        stock_code=args.stock_code,
        order_code=args.order_code,
    )
    fingerprint_path.write_text(new_fingerprint + "\n", encoding="utf-8")
    size_kb = output_path.stat().st_size / 1024
    print(f"Rebuilt {output_path.name} with {count} products ({size_kb:.1f} KB).")


if __name__ == "__main__":
    main()
