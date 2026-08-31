from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .bot import ShopBot
from .config import load_settings
from .security import days_from_now
from .store import Store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="vpn-shop service")
    parser.add_argument(
        "--env-file",
        default=None,
        help="Load an extra dotenv file after .env and let it override base values, e.g. .env.silentconnect",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Initialize local sqlite storage")
    sub.add_parser("run-bot", help="Run Telegram bot long polling loop")
    sub.add_parser("run-web", help="Run public web checkout")

    create_invite = sub.add_parser("create-invite", help="Create invite token")
    create_invite.add_argument("--uses", type=int, default=1)
    create_invite.add_argument("--days", type=int, default=30)
    create_invite.add_argument("--note", default="")

    create_promo = sub.add_parser("create-promo", help="Create promo code")
    create_promo.add_argument("--transport", choices=["xhttp", "tcp", "hybrid"], required=True)
    create_promo.add_argument("--days", type=int, required=True)
    create_promo.add_argument("--discount", type=int, choices=[10, 25, 50, 75, 100], required=True)
    create_promo.add_argument("--device-limit", type=int, choices=[0, 3, 6, 9], default=3)
    create_promo.add_argument("--mode", choices=["anonymous", "family"], required=True)
    create_promo.add_argument("--label", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)

    settings = load_settings(Path(__file__).resolve().parents[1], env_file=args.env_file)
    store = Store(settings.database_path)
    store.init()

    if args.command == "init-db":
        print(settings.database_path)
        return 0

    if args.command == "create-invite":
        code, _ = store.create_invite(max_uses=args.uses, expires_at=days_from_now(args.days), note=args.note)
        print(code)
        return 0

    if args.command == "create-promo":
        label = args.label or None
        if args.mode == "family" and not label:
            raise SystemExit("--label is required for family promo codes")
        code, _ = store.create_promo_code(
            transport=args.transport,
            duration_days=args.days,
            discount_percent=args.discount,
            device_limit=args.device_limit,
            profile_mode=args.mode,
            family_label=label,
        )
        print(code)
        return 0

    if args.command == "run-bot":
        bot = ShopBot(settings, store)
        bot.run_forever()
        return 0

    if args.command == "run-web":
        from .web import serve

        serve(settings, store)
        return 0

    raise SystemExit(f"Unsupported command: {args.command}")
