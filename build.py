#!/usr/bin/env python3
"""
Builds a standalone, zero-dependency searchable product catalog (index.html)
from a Sage Accounting Online Ireland `stock_item_export.csv` file.

Two access codes are supported:
  --view-code   Unlocks the catalogue with prices hidden (and stripped/encrypted).
  --price-code  Unlocks the catalogue with decrypted prices visible.

Usage:
    python3 build.py [path/to/stock_item_export.csv] [--title "Your Store Catalogue"]
"""

import argparse
import base64
import csv
import hashlib
import hmac
import html
import json
import secrets
from pathlib import Path

KEY_ROUNDS = 5000


def normalize_code(code: str) -> str:
    return "".join(code.split()).upper()


def normalize_number(raw: object) -> int | float:
    text = str(raw if raw is not None else "0").replace(",", "").strip()
    try:
        val = round(float(text), 2)
        return int(val) if val.is_integer() else val
    except ValueError:
        return 0


def derive_key(salt: str, code: str) -> bytes:
    h = hashlib.sha256(f"{salt}:{normalize_code(code)}".encode("utf-8")).digest()
    for _ in range(KEY_ROUNDS - 1):
        h = hashlib.sha256(h).digest()
    return h


def verify_hash(key: bytes) -> str:
    return hashlib.sha256(b"VERIFY:" + key).hexdigest()


def wrap_key(secret_key: bytes, wrapping_key: bytes) -> str:
    """XOR-wraps a 32-byte key under another derived key so multiple authorized codes can decrypt prices."""
    mask = hashlib.sha256(b"WRAP:" + wrapping_key).digest()
    wrapped = bytes(a ^ b for a, b in zip(secret_key, mask))
    return base64.b64encode(wrapped).decode("ascii")


def encrypt_prices(prices: list[float], key: bytes) -> str:
    plaintext = json.dumps(prices, separators=(",", ":")).encode("utf-8")
    mac = hashlib.sha256(b"MAC:" + plaintext).digest()[:16]
    payload = mac + plaintext

    out = bytearray(len(payload))
    for block_idx in range((len(payload) + 31) // 32):
        stream = hashlib.sha256(key + block_idx.to_bytes(4, "big")).digest()
        start = block_idx * 32
        end = min(start + 32, len(payload))
        for i in range(start, end):
            out[i] = payload[i] ^ stream[i - start]
    return base64.b64encode(bytes(out)).decode("ascii")


def compute_fingerprint(
    products: list[list],
    prices: list[float],
    template_text: str,
    title: str,
    view_code: str,
    price_code: str,
    stock_code: str = "EPT500",
    order_code: str = "EPT900",
) -> str:
    """Keyed deterministic fingerprint of catalogue inputs so unchanged builds are skipped without leaking prices."""
    key = derive_key("fingerprint", price_code)
    payload = json.dumps(
        {
            "title": title,
            "view_code": normalize_code(view_code),
            "stock_code": normalize_code(stock_code),
            "order_code": normalize_code(order_code),
            "template_sha256": hashlib.sha256(template_text.encode("utf-8")).hexdigest(),
            "products": products,
            "prices": prices,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def render_catalog(
    products: list[list],
    prices: list[float],
    template_path: Path,
    output_path: Path,
    title: str,
    view_code: str,
    price_code: str,
    stock_code: str = "EPT500",
    order_code: str = "EPT900",
) -> int:
    codes = {
        normalize_code(view_code),
        normalize_code(price_code),
        normalize_code(stock_code),
        normalize_code(order_code),
    }
    if len(codes) < 4:
        raise ValueError("view-code, price-code, stock-code, and order-code must all be different")

    salt = secrets.token_hex(8)
    view_key = derive_key(salt, view_code)
    price_key = derive_key(salt, price_code)
    stock_key = derive_key(salt, stock_code)
    order_key = derive_key(salt, order_code)

    view_hash = verify_hash(view_key)
    price_hash = verify_hash(price_key)
    stock_hash = verify_hash(stock_key)
    order_hash = verify_hash(order_key)
    wrapped_price_key = wrap_key(price_key, order_key)
    encrypted_prices = encrypt_prices(prices, price_key)

    template = template_path.read_text(encoding="utf-8")
    products_json = json.dumps(products, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    subtitle = f"{len(products):,} products"

    rendered = (
        template.replace("__TITLE__", html.escape(title))
        .replace("__SUBTITLE__", html.escape(subtitle))
        .replace("__PRODUCTS_JSON__", products_json)
        .replace("__AUTH_SALT__", salt)
        .replace("__VIEW_HASH__", view_hash)
        .replace("__PRICE_HASH__", price_hash)
        .replace("__STOCK_HASH__", stock_hash)
        .replace("__ORDER_HASH__", order_hash)
        .replace("__WRAPPED_PRICE_KEY__", wrapped_price_key)
        .replace("__ENCRYPTED_PRICES__", encrypted_prices)
    )
    output_path.write_text(rendered, encoding="utf-8")
    return len(products)


def build_catalog(
    csv_path: Path,
    template_path: Path,
    output_path: Path,
    title: str,
    view_code: str,
    price_code: str,
    stock_code: str = "EPT500",
    order_code: str = "EPT900",
) -> int:
    products = []
    prices = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            active = (row.get("Active") or "Yes").strip().lower()
            if active not in ("yes", "y", "true", "1", ""):
                continue

            code = (row.get("Item Code*") or row.get("Item Code") or "").strip()
            desc = (row.get("Description*") or row.get("Description") or "").strip()
            if not code or not desc:
                continue

            price = normalize_number(row.get("Sales Price 1 Value"))
            qty = normalize_number(row.get("Quantity In Stock"))
            category = (row.get("Category") or "").strip() or "Other"
            barcode = (row.get("Barcode") or "").strip()

            products.append([code, desc, category, barcode, qty])
            prices.append(price)

    return render_catalog(
        products=products,
        prices=prices,
        template_path=template_path,
        output_path=output_path,
        title=title,
        view_code=view_code,
        price_code=price_code,
        stock_code=stock_code,
        order_code=order_code,
    )


def main() -> None:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Build searchable product catalog from Sage CSV export.")
    parser.add_argument(
        "csv_file",
        nargs="?",
        default=str(here / "stock_item_export.csv"),
        help="Path to stock_item_export.csv",
    )
    parser.add_argument(
        "--title",
        default="Electric Power Tool Co. Ltd.",
        help="Page title / store name",
    )
    parser.add_argument(
        "--view-code",
        default="EPT100",
        help="Access code for catalogue without prices",
    )
    parser.add_argument(
        "--price-code",
        default="EPT749",
        help="Access code for full catalogue with prices",
    )
    parser.add_argument(
        "--stock-code",
        default="EPT500",
        help="Access code for stock take mockup mode",
    )
    parser.add_argument(
        "--order-code",
        default="EPT900",
        help="Access code for salesman order-taking mockup mode",
    )
    parser.add_argument(
        "--out",
        default=str(here / "index.html"),
        help="Output HTML path",
    )
    args = parser.parse_args()

    count = build_catalog(
        csv_path=Path(args.csv_file),
        template_path=here / "template.html",
        output_path=Path(args.out),
        title=args.title,
        view_code=args.view_code,
        price_code=args.price_code,
        stock_code=args.stock_code,
        order_code=args.order_code,
    )
    size_kb = Path(args.out).stat().st_size / 1024
    print(f"Built {args.out} with {count} products ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
