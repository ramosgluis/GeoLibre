"""Administration CLI for the self-hosted Share service."""

from __future__ import annotations

import argparse
import getpass

from .share_store import ShareStore


def main() -> None:
    parser = argparse.ArgumentParser(description="GeoLibre Share local administration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-user")
    create.add_argument("--username", required=True)
    create.add_argument("--admin", action="store_true")
    args = parser.parse_args()

    if args.command == "create-user":
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise SystemExit("Passwords do not match")
        ShareStore().create_user(args.username, password, admin=args.admin)
        print(f"Created user {args.username}")


if __name__ == "__main__":
    main()
