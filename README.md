# S5 Mail to Stalwart

Run `migrate.py` on the Stalwart machine. Python standard library only; requires
`vandelay`, `stalwart-cli`, SSH key access to S5 Mail, and passwordless sudo on
both machines. Tested with Dovecot 2.4.1, Nextcloud 34.0.2 and Vandelay 1.0.10.

```bash
export STALWART_URL=https://mail.example.com
export STALWART_USER=admin@example.com

python3 migrate.py \
  --source admin@OLD_SERVER_IP \
  --identity ~/.ssh/s5mail-migration \
  --components all
```

The script prompts for the Stalwart admin password. For automation, set
`STALWART_PASSWORD` in the environment. The SSH host key must already be known.
The old server needs a distinct legacy hostname with a valid TLS certificate.

Components: `accounts`, `mail`, `sieve`, `carddav`, `caldav`, or `all`.
Combine them with commas, e.g. `--components mail,sieve`. Missing domains and
users are created before content imports; existing accounts are left unchanged.
`accounts` alone does not pause services. Add `--user user@example.com` to select
one mailbox; repeat it for several users.

Content migration pauses source delivery and client access, creates temporary
Dovecot master credentials / Nextcloud app passwords, and imports through SSH
tunnels. Only SSH port 22 needs to be reachable from the new server. Temporary
firewall rules and a local `/etc/hosts` override are removed during cleanup.
No user passwords or manually created app passwords are needed.

**By default, source Postfix, Nginx and Dovecot remain stopped after content
migration, including import failures.** Use `--resume-source` for rehearsals to
restore their initial service state. Keep the new server's clients/delivery
paused until you have verified the import and switched traffic.

Private archives and the user database live in `~/s5mail-migration`. Use
`--work-dir` to change this; reuse it for retries. Export is additive and limited
to the selected component. Owned, writable DAV collections are imported;
generated/read-only views and shared collections are skipped.

If an interrupted run left source recovery state, rerun with
`--cleanup-source` (and `--resume-source` only if restoring source services).
The same source/identity flags are needed. Recovery can be retried if cleanup
fails. Keep `source-agent.py` and `import-miab-account.py` beside `migrate.py`.

Aliases, quotas/admin roles, shared collection permissions, global Sieve rules,
Nextcloud files/settings, DNS cutover and the old Postfix queue are outside the
script. Verify these before retiring the source.

References: [Vandelay](https://stalw.art/docs/migration/import-export/),
[Dovecot master users](https://doc.dovecot.org/2.4.1/core/config/auth/master_users.html),
[Nextcloud authentication tokens](https://docs.nextcloud.com/server/stable/admin_manual/occ_users.html).

Tests: `python3 -m unittest discover -s tests`.

The older `import-miab-account.py` and `migrate-mailboxes.py` entry points remain
available for the previous manual workflow.
