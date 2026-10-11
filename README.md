# S5 Mail to Stalwart

Run `migrate.py` on the Stalwart server to migrate users, mail, user Sieve
scripts, contacts and calendars. Each component can run separately. The script
uses only the Python standard library.

These instructions target [S5 Mail](https://github.com/wtarit/s5mail), a
Mail-in-a-Box fork, with Dovecot `2.4.1-4` and Nextcloud `34.0.2`. Tested with
Vandelay `1.0.10` and stalwart-cli `1.0.12`; no server upgrade is needed.

This workflow accepts downtime to simplify migration. Mail and Sieve can run
first, with contacts and calendars later.

## Prerequisites

- New Stalwart server ready, with working admin credentials and JMAP access. Its advertised JMAP URLs must resolve to new server from new server, even before switching MX. Don't connect clients or switch mail delivery to it yet.
- Python 3, SSH, [Vandelay](https://stalw.art/docs/migration/import-export/installation/) and [stalwart-cli](https://stalw.art/docs/management/cli/) on new server. The script also checks `~/.cargo/bin` for the tools.
- SSH key access from new server to old server, with passwordless `sudo` on both. Only SSH port 22 needs to be reachable between them.
- Old server has a separate hostname and valid TLS certificate. For example, use `legacy.mail.example.com` for old server and `mail.example.com` for Stalwart.
- Don't change users/passwords or rerun S5 Mail setup during migration.

Clone this repository on the new server, or update your existing checkout. Keep `migrate.py`, `source-agent.py` and `import-miab-account.py` together.

From new server, check SSH access once and verify the old server's host key:

```bash
ssh -i ~/.ssh/s5mail-migration admin@OLD_SERVER_IP sudo -n true
sudo -n true
```

`~/.ssh/s5mail-migration` is a dedicated migration key. Use your own authorized key if different. The script requires a known host key and won't accept a new one automatically.

## How it works

1. Connect to S5 Mail over one SSH connection and take a consistent SQLite snapshot of the user database.
2. Create missing Stalwart domains and users, keeping the original password hashes. Existing accounts are left unchanged.
3. Pause old server delivery and client access. Temporary IPv4/IPv6 firewall rules block public mail and web ports; SSH stays available.
4. Create a temporary Dovecot master user for IMAP and ManageSieve. For DAV, create a temporary Nextcloud app password per user through `occ`. Users don't need to provide passwords.
5. Import selected components through SSH tunnels into private SQLite archives, then export them to Stalwart with Vandelay.
6. Revoke app passwords, remove the script's master user/config, close tunnels and remove temporary firewall rules.

The script temporarily maps the legacy hostname to loopback in `/etc/hosts` on new server. This keeps TLS certificate checks working through the tunnels; the temporary mapping is removed during cleanup.

Dovecot's master user can read both mail and user Sieve scripts. S5 Mail doesn't load `conf.d` automatically, so the script adds its own explicit include before the SQL passdb and removes it afterwards. It keeps any existing master user configuration. See [Dovecot 2.4.1 master users](https://doc.dovecot.org/2.4.1/core/config/auth/master_users.html).

Nextcloud uses a separate app password for each user, created and revoked with [authentication token commands](https://docs.nextcloud.com/server/stable/admin_manual/occ_users.html). The script imports owned, writable address books and calendars. It skips generated/read-only views and shared collections. Users without a Nextcloud account are skipped for DAV.

## Run the migration

On new server:

```bash
cd /path/to/miab-to-stalwart
export STALWART_URL=https://mail.example.com
export STALWART_USER=admin@example.com

python3 migrate.py \
  --source admin@OLD_SERVER_IP \
  --identity ~/.ssh/s5mail-migration \
  --components all
```

Enter the Stalwart admin password when prompted. `STALWART_PASSWORD` also works for automation; don't put it in the command or commit it.

By default, all source mail users are selected. Missing accounts are created even when running only a content component.

Use `--components` to choose what to migrate:

| Value | Data |
| --- | --- |
| `accounts` | Missing domains and users only; no service downtime |
| `mail` | IMAP folders, messages and flags |
| `sieve` | User scripts and active script |
| `carddav` | Owned, writable address books and contacts |
| `caldav` | Owned, writable calendars and events |
| `all` | Everything above |

For example, run mail and Sieve first:

```bash
python3 migrate.py \
  --source admin@OLD_SERVER_IP \
  --identity ~/.ssh/s5mail-migration \
  --components mail,sieve
```

Use the same command with `--components carddav,caldav` later. Add `--user user@example.com` to select one user; repeat it for several users.

For a rehearsal, add `--resume-source`. This restores each source service to its initial running/stopped state. Otherwise, content migration leaves old server's Postfix, Nginx and Dovecot stopped, including after an import failure. A later component run starts only the services it needs.

Archives and the user database go in `~/s5mail-migration`, with owner-only permissions. Use `--work-dir` to change this. Keep the same directory when retrying; use a separate directory for another source server. Each component, user and DAV collection has its own archive, and export is limited to that component's object types.

Vandelay export is additive by default. Reruns recognize existing objects, but don't remove unmatched destination data. Keep source data frozen and destination clients away until the final import is verified. See [export behavior](https://stalw.art/docs/migration/import-export/export/).

## Verify and switch traffic

- Check folders, message counts and read/flagged state. Test the original password for newly created users; existing accounts keep their destination credentials.
- Check the active Sieve script and test its rules with a new message.
- Check contacts, calendar events, time zones and recurrence.
- Recreate aliases, quotas/admin roles and sharing permissions before enabling delivery. Global Sieve rules and Nextcloud files/settings are outside this script.
- Switch DNS/client traffic to Stalwart.
- Keep old server for senders using cached DNS. Arrange forwarding to Stalwart and transfer mail left in the old Postfix queue before retiring it; don't resume local delivery into migrated mailboxes.
- Keep archives until migration is verified. They contain private data and password hashes.

## Interrupted runs

If the process or SSH connection was interrupted and cleanup didn't finish, run from new server:

```bash
python3 migrate.py \
  --source admin@OLD_SERVER_IP \
  --identity ~/.ssh/s5mail-migration \
  --cleanup-source
```

Add `--resume-source` only if you want to restore the old services' initial state. Recovery removes only this script's credentials and firewall rules. It keeps recovery state if cleanup fails, so the command can be retried.

Protocol references: [IMAP](https://stalw.art/docs/migration/import-export/import/imap/), [ManageSieve](https://stalw.art/docs/migration/import-export/import/managesieve/), [CardDAV](https://stalw.art/docs/migration/import-export/import/carddav/) and [CalDAV](https://stalw.art/docs/migration/import-export/import/caldav/).

## Tests

```bash
python3 -m unittest discover -s tests
```

See [TESTING.md](TESTING.md) for the live end-to-end test results.

The older `import-miab-account.py` and `migrate-mailboxes.py` entry points remain
available for the previous manual workflow. `migrate.py` is the entry point for
the workflow above.
