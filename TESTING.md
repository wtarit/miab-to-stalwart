# Verification

Live end-to-end tests completed on October 10, 2026 (Pacific time), using the
user's two test instances: S5 Mail with Dovecot 2.4.1-4 / Nextcloud 34.0.2, and
Stalwart 1.0.0 with Vandelay 1.0.10 / stalwart-cli 1.0.12.

Dedicated fixtures covered:

- Missing domain/account creation, original password login, existing accounts
  left unchanged, and repeated `--user` selection.
- Mail folder placement, message text, unread/seen/flagged state and empty mailboxes.
- User Sieve scripts, active-script selection, and a new SMTP message routed by
  the migrated rule.
- Contact name/email/phone and calendar event UID/start/duration.
- Owned DAV collection discovery; generated/read-only views excluded, and users
  without Nextcloud accounts skipped.
- Admin-created Nextcloud app passwords with no user login password, including
  authentication as an existing IMAP-backed Nextcloud user.
- Separate mail, Sieve, contacts and calendar runs; unselected content unchanged.
- Repeated imports/exports with stable object identities and no duplicates.
- Public source ports blocked while SSH/tunnel access remained available.
- Forced Vandelay failure: credentials, includes, hostname override, forwards
  and firewall rules removed; default source services left stopped.
- Interrupted-run recovery through `--cleanup-source --resume-source`: temporary
  credentials/rules removed and the initial service states restored.

Fixture accounts, their content, the test domain and its generated DKIM records
were removed afterwards. Existing users/data and the pre-existing Dovecot master
configuration were preserved. Source Dovecot was left running; source Postfix and
Nginx were left stopped, matching the initial state.

Local tests: `python3 -m unittest discover -s tests` (six tests). These exercise
DAV ownership/endpoint filtering, preservation of existing account credentials,
SQLite WAL snapshots, retryable cleanup after a token backend failure, and
removal of stale hostname overrides before reconnecting for recovery.

The updated blog passed `pnpm build` in the personal-blog repository.
