#!/usr/bin/env python3

import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path


REQUIRED_ENV_VARS = (
    "MIAB_DB",
    "MIAB_IMAP_URL",
    "MIAB_SIEVE_URL",
    "MIAB_MASTER_USER",
    "MIAB_MASTER_PASSWORD",
    "ARCHIVE_ROOT",
    "STALWART_URL",
    "STALWART_USER",
    "STALWART_PASSWORD",
)


def run_vandelay(*args, password):
    env = {**os.environ, "VANDELAY_PASSWORD": password}
    subprocess.run(["vandelay", *args], env=env, check=True)


def main():
    missing = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
    if missing:
        raise ValueError(f"Missing required environment variable(s): {', '.join(missing)}")

    config = os.environ
    db = Path(config["MIAB_DB"])
    if not db.is_file():
        raise ValueError(f"MIAB_DB does not exist or is not a file: {db}")
    if not shutil.which("vandelay"):
        raise ValueError("Required command not found: vandelay")

    # Read the same user database as import-miab-account.py without modifying it.
    with sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True) as conn:
        emails = [row[0] for row in conn.execute("SELECT email FROM users ORDER BY email")]

    for email in emails:
        if (
            not isinstance(email, str)
            or email.count("@") != 1
            or any(c in email for c in "/\r\n")
        ):
            raise ValueError("Invalid mailbox email in users database")

    # Archives contain private mail. New directories/files are owner-only.
    os.umask(0o077)
    archive_root = Path(config["ARCHIVE_ROOT"])
    archive_root.mkdir(parents=True, exist_ok=True)

    for email in emails:
        archive = str(archive_root / f"{email}.sqlite")
        login = f"{email}%{config['MIAB_MASTER_USER']}"
        print(f"\nMigrating: {email}", flush=True)

        for protocol, url in (
            ("imap", config["MIAB_IMAP_URL"]),
            ("managesieve", config["MIAB_SIEVE_URL"]),
        ):
            print(f"Importing from Mail-in-a-Box over {protocol}...", flush=True)
            run_vandelay(
                "import", protocol,
                "--url", url,
                "--auth-basic", login,
                archive,
                password=config["MIAB_MASTER_PASSWORD"],
            )

        print("Exporting to Stalwart...", flush=True)
        run_vandelay(
            "export",
            "--url", config["STALWART_URL"],
            "--auth-basic", config["STALWART_USER"],
            "--account-name", email,
            archive,
            password=config["STALWART_PASSWORD"],
        )
        print(f"Done: {email}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: Vandelay failed with exit code {exc.returncode}.", file=sys.stderr)
        sys.exit(exc.returncode if exc.returncode > 0 else 1)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
