#!/usr/bin/env python3

import argparse
import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def run_cli(*args, input_json=None):
    """Run stalwart-cli and return stdout."""
    cmd = ["stalwart-cli", *args]

    result = subprocess.run(
        cmd,
        input=json.dumps(input_json) if input_json is not None else None,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        print(f"ERROR running: {' '.join(cmd)}", file=sys.stderr)
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)
        raise RuntimeError(f"stalwart-cli exited with {result.returncode}")

    return result.stdout


def read_ndjson(output):
    """Parse stalwart-cli --json NDJSON output."""
    records = []

    for line in output.splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))

    return records


def get_domains():
    output = run_cli(
        "query",
        "Domain",
        "--fields",
        "id,name",
        "--json",
    )

    domains = {}

    for item in read_ndjson(output):
        domains[item["name"].lower()] = item["id"]

    return domains


def get_existing_accounts(domains_by_name):
    output = run_cli(
        "query",
        "Account",
        "--fields",
        "id,name,domainId",
        "--json",
    )

    # Reverse mapping:
    # domain ID -> domain name
    domain_names = {
        domain_id: domain_name for domain_name, domain_id in domains_by_name.items()
    }

    existing = set()

    for item in read_ndjson(output):
        domain_id = item.get("domainId")
        local_part = item.get("name")

        if not domain_id or not local_part:
            continue

        domain = domain_names.get(domain_id)

        if domain:
            existing.add(f"{local_part}@{domain}".lower())

    return existing


def get_miab_users(db_path):
    conn = sqlite3.connect(db_path)

    try:
        rows = conn.execute(
            """
            SELECT email, password
            FROM users
            ORDER BY email
            """
        ).fetchall()
    finally:
        conn.close()

    return rows


def normalize_password_hash(password):
    """
    MIAB/Dovecot stores hashes like:

        {SHA512-CRYPT}$6$rounds=5000$...

    Stalwart understands the crypt hash itself:

        $6$rounds=5000$...
    """

    prefix = "{SHA512-CRYPT}"

    if password.startswith(prefix):
        return password[len(prefix) :]

    # Already raw SHA512-CRYPT.
    if password.startswith("$6$"):
        return password

    raise ValueError(f"Unsupported password format: {password[:30]!r}")


def create_user(email, password_hash, domain_id):
    local_part, _domain = email.rsplit("@", 1)

    payload = {
        "name": local_part,
        "domainId": domain_id,
        "description": email,
        "credentials": {
            "0": {
                "@type": "Password",
                "secret": password_hash,
            }
        },
    }

    # --stdin keeps the password hash out of command-line arguments.
    run_cli(
        "create",
        "Account/User",
        "--stdin",
        input_json=payload,
    )


def invalidate_caches():
    run_cli(
        "create",
        "Action",
        "--json",
        '{"@type":"InvalidateCaches"}',
    )


def main():
    parser = argparse.ArgumentParser(
        description="Import Mail-in-a-Box users into Stalwart."
    )

    parser.add_argument(
        "--db",
        required=True,
        type=Path,
        help="Path to Mail-in-a-Box users.sqlite",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would happen without creating accounts.",
    )

    args = parser.parse_args()

    if not args.db.is_file():
        print(f"ERROR: database does not exist: {args.db}", file=sys.stderr)
        sys.exit(1)

    print("Reading Stalwart domains...")
    domains = get_domains()

    print(f"Found {len(domains)} Stalwart domain(s).")

    print("Reading existing Stalwart accounts...")
    existing_accounts = get_existing_accounts(domains)

    print(f"Found {len(existing_accounts)} existing Stalwart account(s).")

    print("Reading Mail-in-a-Box users...")
    users = get_miab_users(args.db)

    to_import = []
    skipped = []
    missing_domain = []
    invalid_password = []

    for email, password in users:
        email = email.lower()
        local_part, domain = email.rsplit("@", 1)

        if email in existing_accounts:
            skipped.append(email)
            continue

        if domain not in domains:
            missing_domain.append(email)
            continue

        try:
            normalized_hash = normalize_password_hash(password)
        except ValueError as exc:
            invalid_password.append((email, str(exc)))
            continue

        to_import.append((email, normalized_hash, domains[domain]))

    print()
    print("Migration plan")
    print("==============")
    print(f"MIAB users:             {len(users)}")
    print(f"Already exist / skip:   {len(skipped)}")
    print(f"Will import:            {len(to_import)}")
    print(f"Missing domain:         {len(missing_domain)}")
    print(f"Unsupported password:   {len(invalid_password)}")

    if skipped:
        print()
        print("Existing accounts (will skip)")
        print("--------------------------------")
        for email in skipped:
            print(f"SKIP    {email}")

    if missing_domain:
        print()
        print("Missing domains")
        print("---------------")
        for email in missing_domain:
            print(f"MISSING {email}")

    if invalid_password:
        print()
        print("Unsupported password hashes")
        print("---------------------------")
        for email, reason in invalid_password:
            print(f"ERROR   {email}: {reason}")

    if args.dry_run:
        print()
        print("Dry run complete. No changes made.")
        return

    if missing_domain or invalid_password:
        print()
        print("ERROR: migration aborted because some accounts cannot be imported.")
        print("Fix missing domains/password formats and run again.")
        sys.exit(1)

    if not to_import:
        print()
        print("Nothing to import.")
        return

    print()
    print("Importing users")
    print("===============")

    created = 0
    failed = []

    for email, password_hash, domain_id in to_import:
        try:
            create_user(email, password_hash, domain_id)
            created += 1
            print(f"CREATE  {email}")
        except Exception as exc:
            failed.append((email, str(exc)))
            print(f"FAILED  {email}: {exc}", file=sys.stderr)

    if created:
        print()
        print("Invalidating Stalwart caches...")

        try:
            invalidate_caches()
        except Exception as exc:
            print(
                f"WARNING: cache invalidation failed: {exc}",
                file=sys.stderr,
            )

    print()
    print("Result")
    print("======")
    print(f"MIAB users:    {len(users)}")
    print(f"Skipped:       {len(skipped)}")
    print(f"Created:       {created}")
    print(f"Failed:        {len(failed)}")

    if failed:
        print()
        print("Failed accounts")
        print("---------------")

        for email, error in failed:
            print(f"{email}: {error}")

        sys.exit(1)


if __name__ == "__main__":
    main()
