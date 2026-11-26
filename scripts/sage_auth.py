#!/usr/bin/env python3
"""
One-time interactive helper to authorize Sage Business Cloud Accounting (Ireland)
and print the initial SAGE_REFRESH_TOKEN and SAGE_BUSINESS_ID for GitHub Secrets.

Requirements:
- Python 3 (standard library only, no pip install needed).
- Your Sage app on https://developerselfservice.sageone.com/ must include
  `http://localhost:8080/callback` in its Callback URLs.

Usage:
    python3 scripts/sage_auth.py
"""

from __future__ import annotations

import getpass
import http.server
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

REDIRECT_URI = "http://localhost:8080/callback"
AUTH_URL = "https://www.sageone.com/oauth2/auth/central"
TOKEN_URL = "https://oauth.accounting.sage.com/token"
API_BASE = "https://api.accounting.sage.com/v3.1"


def main() -> None:
    print("=== Sage Business Cloud Accounting (Ireland) — One-Time Auth ===\n")
    client_id = input("Sage Client ID: ").strip()
    client_secret = getpass.getpass("Sage Client Secret (hidden): ").strip()
    if not client_id or not client_secret:
        raise SystemExit("Both Client ID and Client Secret are required.")

    state = secrets.token_urlsafe(16)
    auth_params = urllib.parse.urlencode(
        {
            "filter": "apiv3.1",
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": "readonly",
            "country": "ie",
            "state": state,
        }
    )
    full_auth_url = f"{AUTH_URL}?{auth_params}"

    result: dict[str, str] = {}

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return

            qs = urllib.parse.parse_qs(parsed.query)
            if "error" in qs:
                result["error"] = qs["error"][0]
                msg = f"Sage authorization failed: {result['error']}. You can close this tab."
            elif qs.get("state", [""])[0] != state:
                result["error"] = "state_mismatch"
                msg = "Security state mismatch. Please retry."
            elif "code" in qs:
                result["code"] = qs["code"][0]
                msg = "Authorization received! Return to your terminal window — you can close this tab."
            else:
                result["error"] = "missing_code"
                msg = "No authorization code returned."

            body = f"<html><body style='font-family:sans-serif;padding:2rem'><h2>{msg}</h2></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", 8080), CallbackHandler)

    print("\nOpening Sage Ireland login in your browser...")
    print("Sign in with your SAGE ACCOUNTING COMPANY login (NOT your developer login) and click Allow.\n")
    print(f"If your browser does not open automatically, copy this URL:\n{full_auth_url}\n")
    webbrowser.open(full_auth_url)

    print("Waiting for Sage redirect on http://localhost:8080/callback ...")
    while not result:
        server.handle_request()
    server.server_close()

    if "error" in result:
        raise SystemExit(f"Authorization failed: {result['error']}")

    print("Exchanging authorization code for tokens...")
    token_payload = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": result["code"],
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        TOKEN_URL,
        data=token_payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            tokens = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Token exchange failed (HTTP {exc.code}): {err}") from exc

    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    if not refresh_token:
        raise SystemExit(f"Unexpected token response: {tokens}")

    # List available businesses so the user can confirm/pin SAGE_BUSINESS_ID.
    businesses: list[dict] = []
    if access_token:
        biz_req = urllib.request.Request(
            f"{API_BASE}/businesses",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(biz_req, timeout=30) as resp:
                businesses = json.loads(resp.read().decode("utf-8")).get("$items") or []
        except Exception as exc:  # noqa: BLE001
            print(f"Note: could not list businesses ({exc})", file=sys.stderr)

    print("\n" + "=" * 64)
    print("SUCCESS! Add these to GitHub -> Settings -> Secrets -> Actions:")
    print("=" * 64)
    print(f"\nSAGE_CLIENT_ID:\n{client_id}")
    print(f"\nSAGE_CLIENT_SECRET:\n(the Client Secret you just entered)")
    print(f"\nSAGE_REFRESH_TOKEN:\n{refresh_token}")

    if businesses:
        print("\nSAGE_BUSINESS_ID (optional, recommended if you have >1 company):")
        for b in businesses:
            print(f"  - {b.get('displayed_as', 'Unknown')}: {b.get('id', '')}")
    print("\nKeep SAGE_REFRESH_TOKEN private and do not run this script again unless re-authorizing.")


if __name__ == "__main__":
    main()
