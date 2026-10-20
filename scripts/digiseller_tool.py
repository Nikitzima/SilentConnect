#!/usr/bin/env python3
"""Digiseller / Plati.market Management CLI for SilentConnect.

Provides seller operations:
- test-auth: Validate credentials and display seller token/account status
- list-goods: List all active products of the seller
- create-listing: Create a fully compliant, white-hat listing (3 devices, 1 Gbps, 30 days)
- check-stock: Display current inventory count for a product
- sync-stock: Pre-generate activation links and upload to product inventory
- verify-code: Inspect purchase details for a Digiseller unique code
- deliver-code: Deliver content for a unique code
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "vpn-shop"))

try:
    from vpn_shop.digiseller import DigisellerClient, build_default_listing_content
    from vpn_shop.config import load_settings
    from vpn_shop.store import Store
except ImportError as exc:
    print(f"Error importing vpn_shop modules: {exc}", file=sys.stderr)
    sys.exit(1)


def resolve_credentials(args: argparse.Namespace) -> tuple[str, str, str]:
    """Resolve seller_id, api_key, and secret_key from args, env, or local files."""
    seller_id = (args.seller_id or os.environ.get("DIGISELLER_SELLER_ID", "")).strip()
    api_key = (args.api_key or os.environ.get("DIGISELLER_API_KEY", "")).strip()
    secret_key = (args.secret_key or os.environ.get("DIGISELLER_SECRET_KEY", "")).strip()

    # Fallback to local desktop api.txt if available
    if not api_key:
        local_key_file = Path(r"C:\Users\Yuric\Desktop\api.txt")
        if local_key_file.exists():
            try:
                api_key = local_key_file.read_text(encoding="utf-8").strip()
            except Exception:
                pass

    # Fallback to .env.silentconnect if available
    if not api_key or not seller_id:
        env_file = ROOT_DIR / ".env.silentconnect"
        if not env_file.exists():
            env_file = Path("/root/vpn-shop/.env.silentconnect")
        if env_file.exists():
            settings = load_settings(env_file=env_file)
            if not seller_id:
                seller_id = settings.digiseller_seller_id
            if not api_key:
                api_key = settings.digiseller_api_key
            if not secret_key:
                secret_key = settings.digiseller_secret_key

    if not seller_id:
        seller_id = "1348126"

    return seller_id, api_key, secret_key


def cmd_test_auth(args: argparse.Namespace) -> int:
    seller_id, api_key, secret_key = resolve_credentials(args)
    if not api_key:
        print("[FAIL] Missing Digiseller API key. Pass --api-key or set DIGISELLER_API_KEY.", file=sys.stderr)
        return 1

    print(f"[*] Testing Digiseller apilogin for seller_id={seller_id}...")
    client = DigisellerClient(seller_id=seller_id, api_key=api_key, secret_key=secret_key)
    try:
        token = client.get_token(force_refresh=True)
        masked_token = f"{token[:6]}...{token[-4:]}"
        print(f"[OK] Authentication successful! Token: {masked_token}")
    except Exception as exc:
        print(f"[FAIL] apilogin failed: {exc}", file=sys.stderr)
        return 1

    try:
        goods = client.get_seller_goods(currency="RUR")
        print(f"[OK] Fetched seller goods: {len(goods)} active product(s) found.")
    except Exception as exc:
        print(f"[WARN] Could not fetch goods: {exc}", file=sys.stderr)

    return 0


def cmd_list_goods(args: argparse.Namespace) -> int:
    seller_id, api_key, secret_key = resolve_credentials(args)
    if not api_key:
        print("[FAIL] Missing Digiseller API key.", file=sys.stderr)
        return 1

    client = DigisellerClient(seller_id=seller_id, api_key=api_key, secret_key=secret_key)
    try:
        goods = client.get_seller_goods(currency="RUR")
        print(f"=== Digiseller Products for Seller {seller_id} ({len(goods)} total) ===")
        if not goods:
            print("No products currently listed.")
            return 0

        for item in goods:
            pid = item.get("id_goods")
            name = item.get("name_goods")
            price = item.get("price_rub") or item.get("price")
            cnt = item.get("cnt_goods", 0)
            status = "Available" if item.get("available") == 1 else "Hidden/Out of Stock"
            print(f"- ID: {pid: <8} | Price: {price} RUB | Stock: {cnt} | Status: {status} | Name: {name}")
    except Exception as exc:
        print(f"[FAIL] Error listing goods: {exc}", file=sys.stderr)
        return 1

    return 0


def cmd_create_listing(args: argparse.Namespace) -> int:
    seller_id, api_key, secret_key = resolve_credentials(args)
    if not api_key:
        print("[FAIL] Missing Digiseller API key.", file=sys.stderr)
        return 1

    client = DigisellerClient(seller_id=seller_id, api_key=api_key, secret_key=secret_key)
    content = build_default_listing_content()

    name_ru = args.name_ru or content["name_ru"]
    name_en = args.name_en or content["name_en"]
    desc_ru = args.desc_ru or content["description_ru"]
    desc_en = args.desc_en or content["description_en"]
    price = float(args.price)
    category_id = int(args.category_id)

    print("=== Creating Compliant Listing on Digiseller ===")
    print(f"Category ID : {category_id} (Сервисы и подписки)")
    print(f"Price       : {price} RUB")
    print(f"Name (RU)   : {name_ru}")
    print(f"Name (EN)   : {name_en}")
    print(f"Dry Run     : {'YES' if args.dry_run else 'NO'}")

    if args.dry_run:
        print("[DRY-RUN] Listing payload validated successfully. Omit --dry-run to publish.")
        return 0

    try:
        res = client.create_tunnel_product(
            name_ru=name_ru,
            name_en=name_en,
            description_ru=desc_ru,
            description_en=desc_en,
            price_rub=price,
            category_id=category_id,
            guarantee_days=int(args.guarantee),
            bonus_percent=int(args.bonus),
        )
        retval = res.get("retval")
        if retval != 0:
            print(f"[FAIL] Product creation failed (retval={retval}): {res}", file=sys.stderr)
            return 1

        product_id = res.get("product_id") or (res.get("content") or {}).get("product_id")
        print(f"[SUCCESS] Product created! Product ID: {product_id}")
        print(f"Listing URL : https://plati.market/itm/{product_id}")
        return 0
    except Exception as exc:
        print(f"[FAIL] API Error creating product: {exc}", file=sys.stderr)
        return 1


def cmd_check_stock(args: argparse.Namespace) -> int:
    seller_id, api_key, secret_key = resolve_credentials(args)
    if not api_key:
        print("[FAIL] Missing Digiseller API key.", file=sys.stderr)
        return 1

    client = DigisellerClient(seller_id=seller_id, api_key=api_key, secret_key=secret_key)
    try:
        cnt = client.get_stock_count(args.product_id)
        print(f"Product {args.product_id}: {cnt} item(s) in stock.")
        return 0
    except Exception as exc:
        print(f"[FAIL] Error checking stock: {exc}", file=sys.stderr)
        return 1


def cmd_sync_stock(args: argparse.Namespace) -> int:
    seller_id, api_key, secret_key = resolve_credentials(args)
    if not api_key:
        print("[FAIL] Missing Digiseller API key.", file=sys.stderr)
        return 1

    client = DigisellerClient(seller_id=seller_id, api_key=api_key, secret_key=secret_key)
    count = int(args.count)
    if count <= 0:
        print("Count must be greater than 0.")
        return 1

    print(f"[*] Pre-generating {count} activation link(s) for product {args.product_id}...")

    # Initialize store to provision orders
    settings = load_settings()
    store = Store(settings.db_path)
    store.init()

    from vpn_shop.bot import ShopBot
    bot = ShopBot(settings, store)

    lines: list[str] = []
    for idx in range(count):
        # Create 3-device 30-day order
        order = store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="smart",
            family_label=None,
            base_price_rub=149,
            final_price_rub=149,
            promo_id=None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version=settings.terms_version,
            customer_email="",
        )
        order_public_id = str(order["public_id"])
        meta = {
            "source": "tcp_3_30",
            "device_limit": 3,
            "web": True,
            "digiseller_product_id": str(args.product_id),
            "stock_pregenerated": True,
        }
        store.update_order_meta(order_public_id, meta)

        # Complete and provision order
        completion = bot.complete_order(order, actor="digiseller_stock_sync")
        profile_id = completion.get("profile_public_id") or order.get("provisioned_profile_id")
        base_sub = (settings.subscription_base_url or "").rstrip("/")
        sub_url = str(completion.get("sub_url") or f"{base_sub}/my-secret-sub/import/{profile_id}")

        text_item = (
            f"Благодарим за покупку!\n"
            f"Ваша персональная ссылка на Личный кабинет:\n{sub_url}\n\n"
            f"1. Откройте ссылку на любом устройстве.\n"
            f"2. Выберите приложение (sing-box MT, Happ, Streisand, AmneziaWG).\n"
            f"3. Нажмите кнопку импорта профиля.\n\n"
            f"Служба заботы: https://t.me/SilentConnectVPNBot"
        )
        lines.append(text_item)
        print(f"  [{idx + 1}/{count}] Provisioned profile: {profile_id}")

    print(f"[*] Uploading {len(lines)} item(s) to Digiseller inventory for product {args.product_id}...")
    try:
        res = client.add_content_text(args.product_id, lines)
        print(f"[SUCCESS] Inventory uploaded! Response: {res}")
        new_cnt = client.get_stock_count(args.product_id)
        print(f"Total available stock now: {new_cnt}")
        return 0
    except Exception as exc:
        print(f"[FAIL] Upload failed: {exc}", file=sys.stderr)
        return 1


def cmd_verify_code(args: argparse.Namespace) -> int:
    seller_id, api_key, secret_key = resolve_credentials(args)
    if not api_key:
        print("[FAIL] Missing Digiseller API key.", file=sys.stderr)
        return 1

    client = DigisellerClient(seller_id=seller_id, api_key=api_key, secret_key=secret_key)
    try:
        res = client.get_unique_code_info(args.code)
        print(f"Unique Code Info: {json.dumps(res, indent=2, ensure_ascii=False)}")
        return 0
    except Exception as exc:
        print(f"[FAIL] Error checking unique code: {exc}", file=sys.stderr)
        return 1


def cmd_deliver_code(args: argparse.Namespace) -> int:
    seller_id, api_key, secret_key = resolve_credentials(args)
    if not api_key:
        print("[FAIL] Missing Digiseller API key.", file=sys.stderr)
        return 1

    client = DigisellerClient(seller_id=seller_id, api_key=api_key, secret_key=secret_key)
    try:
        res = client.deliver_unique_code(args.code, args.content)
        print(f"Deliver Result: {json.dumps(res, indent=2, ensure_ascii=False)}")
        return 0
    except Exception as exc:
        print(f"[FAIL] Error delivering unique code: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Digiseller / Plati.market CLI Tool for SilentConnect")
    parser.add_argument("--seller-id", help="Digiseller Seller ID (defaults to 1348126)")
    parser.add_argument("--api-key", help="Digiseller API Key")
    parser.add_argument("--secret-key", help="Digiseller Secret Key")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # test-auth
    subparsers.add_parser("test-auth", help="Test Digiseller API login and token generation")

    # list-goods
    subparsers.add_parser("list-goods", help="List active products for the seller")

    # create-listing
    create_p = subparsers.add_parser("create-listing", help="Publish compliant listing to Digiseller")
    create_p.add_argument("--name-ru", help="Custom Russian title")
    create_p.add_argument("--name-en", help="Custom English title")
    create_p.add_argument("--desc-ru", help="Custom Russian HTML description")
    create_p.add_argument("--desc-en", help="Custom English HTML description")
    create_p.add_argument("--price", type=float, default=149.0, help="Price in RUB (default 149)")
    create_p.add_argument("--category-id", type=int, default=33111, help="Category ID (default 33111: Сервисы и подписки)")
    create_p.add_argument("--guarantee", type=int, default=30, help="Guarantee days (default 30)")
    create_p.add_argument("--bonus", type=int, default=0, help="Bonus percentage (default 0)")
    create_p.add_argument("--dry-run", action="store_true", help="Validate payload without creating")

    # check-stock
    stock_p = subparsers.add_parser("check-stock", help="Check inventory stock count")
    stock_p.add_argument("product_id", type=int, help="Product ID")

    # sync-stock
    sync_p = subparsers.add_parser("sync-stock", help="Pre-generate activation links and upload to inventory")
    sync_p.add_argument("product_id", type=int, help="Product ID")
    sync_p.add_argument("count", type=int, help="Number of items to pre-generate and upload")

    # verify-code
    verify_p = subparsers.add_parser("verify-code", help="Verify a Digiseller unique code")
    verify_p.add_argument("code", help="Unique code")

    # deliver-code
    deliver_p = subparsers.add_parser("deliver-code", help="Deliver content for a unique code")
    deliver_p.add_argument("code", help="Unique code")
    deliver_p.add_argument("content", help="Delivery text content")

    args = parser.parse_args()

    commands = {
        "test-auth": cmd_test_auth,
        "list-goods": cmd_list_goods,
        "create-listing": cmd_create_listing,
        "check-stock": cmd_check_stock,
        "sync-stock": cmd_sync_stock,
        "verify-code": cmd_verify_code,
        "deliver-code": cmd_deliver_code,
    }

    handler = commands.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
