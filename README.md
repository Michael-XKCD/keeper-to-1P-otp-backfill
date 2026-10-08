# keeper-to-1P-otp-backfill

[![check](https://github.com/Michael-XKCD/keeper-to-1P-otp-backfill/actions/workflows/check.yml/badge.svg)](https://github.com/Michael-XKCD/keeper-to-1P-otp-backfill/actions/workflows/check.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![Licence](https://img.shields.io/badge/licence-MIT-green)

Adds the 2FA codes a Keeper to 1Password migration left behind.

1Password's Keeper importer only reads a TOTP seed from Keeper's built-in
one-time-password field. Seeds kept anywhere else (a custom field, a note, a
pasted `otpauth://` URL) don't come across. The password arrives, the 2FA code
doesn't.

This tool reads those seeds from Keeper, finds the 1Password item each record
became, and adds the missing one-time-password field.

```
Keeper (SSO) -> match -> safety checks -> write 1Password -> verify -> report
```

After each write, 1Password must generate a code from the new field. If it
can't, that record is reported as failed. Codes are never displayed.

> **Migrating off Keeper?** Take a full backup first, with revision history.
> See [keeper-vault-backup](https://github.com/Michael-XKCD/keeper-vault-backup).

## Before you run it

- **Nothing is written without `--apply`.** A plain run only reports. Start there.
- **One vault per shared folder.** The cross-vault check assumes your import
  made one 1Password vault per Keeper shared folder. If it didn't, see
  [Cross-vault matches](#cross-vault-matches).
- **Passkeys and file attachments can be lost.** Writes go through `op`'s JSON
  template, which drops passkeys and attachments. Items with a visible passkey
  are refused, but `op` 2.39.0 may not show every passkey. If an item might hold
  one, add its code by hand. 1Password's item history is the only way back.

## Requirements

- **macOS.** Employee/Private vaults are only reachable through the desktop app, not a service account.
- **Python 3.11+**
- **[1Password CLI](https://developer.1password.com/docs/cli/get-started/)** (`op`), with the desktop app unlocked and *Settings -> Developer -> Integrate with 1Password CLI* on
- **A Keeper account that signs in with SSO.** Master-password login is not supported.

## Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install '.[live]'
```

The `live` extra pins the Keeper SDK to one exact version, so the code you
audited is the code you run.

## Use

Report only, writes nothing:

```bash
otp-backfill
```

Show the planned writes, then write after you type `yes`:

```bash
otp-backfill --apply --confirm
```

| Flag | |
|---|---|
| `--apply` | actually write; without it the run only reports |
| `--confirm` | show the planned writes and wait for `yes` before applying |
| `--only TITLE` | limit to records with this title; repeatable |
| `--keeper-user EMAIL` | Keeper account to sign in as. **Required for any non-interactive run** |
| `--keeper-server HOST` | Keeper region host, if not the default |
| `--op-account ACCOUNT` | 1Password account, if `op` has more than one |
| `--json-summary PATH` | write a machine-readable summary (mode 0600) |
| `-v`, `--verbose` | more detail on stderr |
| `--version` | print the version |

Interactive runs ask for your Keeper email. Set `OTP_BACKFILL_EMAIL_DOMAIN` to
pre-fill `<your-mac-username>@<that-domain>`. Pass `--keeper-user` to skip the
prompt.

## Safeguards

A wrong code is worse than a missing one. A missing code is still in Keeper. A
wrong one puts 2FA on someone else's account and locks *them* out. So when in
doubt, the tool flags the record and skips it.

### Hard limits

Built into the code:

- **No deletes.** The tool has no delete call.
- **No overwrites.** An item that already has a code is left alone.
- **No writes to Keeper.** The Keeper connection only allows sign-in, sync, and sign-out.
- **One new field only.** Everything else on the item goes back unchanged. If `op` ever returns a masked value, the tool stops instead of saving it.

### Matching rules

| Situation | What happens |
|---|---|
| One match | Write |
| Several matches, one vault, same username | Write to all (one account, duplicated by repeated imports) |
| Several matches, different usernames, none matching the record | **Refuse**, flag |
| Two Keeper records resolve to one item with different seeds | **Refuse**, flag |
| Two Keeper records resolve to one item with the same seed | Written once, the twin reported as a duplicate |
| Matches in more than one vault | **Refuse**, unless Keeper's shared folders name exactly one of them |
| No match | **Refuse**, flag |
| Item already has a code | Leave it, report |
| Item appears to hold a passkey | **Refuse**, flag |
| Keeper record has two conflicting 2FA fields | **Refuse**, flag |

### Cross-vault matches

Two items with the same title in two vaults could be one shared account or two
different ones. 1Password can't tell. Keeper can: it knows which **shared
folder** holds the record. The tool writes only when exactly one matching vault
lines up with one of those folders. Otherwise it refuses.

The top-level shared folder is what counts. A record in `Engineering > AWS`
became an item in the **Engineering** vault.

> **This only works if your import made one 1Password vault per Keeper shared
> folder.** If it mapped folders differently, treat every cross-vault match as a
> refusal.

## How seeds are handled

- **Copied byte for byte.** Seeds are never parsed or changed, so any format Keeper holds survives.
- **Wrapped in a `Secret`.** It prints as `<redacted>`, can't be pickled, and compares in constant time. Only one place in the code unwraps it.
- **Only clear seeds are read.** A field counts as a seed only if it has an OTP type, an OTP label, or an `otpauth` prefix. Labels like "Secret Key" and "API Key" are skipped.
- **Never a command argument.** Other processes can see `op` arguments, so the item goes to `op` on stdin. Never argv, never a file on disk.
- **Scrubbed from output.** Logs, errors, and the report are filtered for anything that looks like a seed, including vendor SDK logs. This is a backup layer under `Secret`, not the main defence.

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

No Keeper or 1Password access needed. Fixture seeds are the public RFC 6238
demo values.

## Licence

MIT - see [LICENSE](LICENSE).
