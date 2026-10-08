# keeper-otp-backfill

[![check](https://github.com/Michael-XKCD/keeper-otp-backfill/actions/workflows/check.yml/badge.svg)](https://github.com/Michael-XKCD/keeper-otp-backfill/actions/workflows/check.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![Licence](https://img.shields.io/badge/licence-MIT-green)

Adds the 2FA codes a Keeper to 1Password migration left behind.

1Password's Keeper importer reads a TOTP seed only from Keeper's native
one-time-password field. Seeds stored anywhere else - a custom field, a note, an
`otpauth://` URL pasted into a text field - never came across. The password
arrived, the second factor did not.

This reads the seeds from Keeper, works out which 1Password item each Keeper
record became, and adds a one-time-password field to the items missing one.

```
Keeper (SSO) -> match -> guard -> write 1Password -> verify -> report
```

After writing, it asks 1Password to generate a code from what was stored. If it
can't, the record is reported as failed rather than quietly counted as done. The
code itself is never displayed.

## Before you run it

**It writes nothing without `--apply`.** A bare run reports what it would do.
Start there.

**Check the precondition.** The cross-vault safety rule assumes your import
created one 1Password vault per Keeper shared folder. If yours didn't, that rule
is unsound for you - see [The guard](#the-guard).

**Passkeys and file attachments.** `op` documents that writing a JSON template
overwrites a passkey, and that is the write path used here. The same applies to
file attachments, which the template does not carry either. The tool refuses any
item whose JSON shows a passkey marker, **but that check is a floor, not a
guarantee**: `op` 2.39.0 does not appear to expose passkeys in `--format=json` at
all, so an item could carry one this cannot see.

The alternative write form puts the seed in a command argument, which `op` warns
is visible to other processes and recorded in shell history, so it was ruled out.
If a target item might hold a passkey, add its code by hand instead. 1Password
keeps item version history, which is the only recovery if one is lost.

## Requirements

- **macOS.** The 1Password CLI reaches Employee/Private vaults through the desktop app's authentication; a service account cannot.
- **Python 3.11+**
- **[1Password CLI](https://developer.1password.com/docs/cli/get-started/)** (`op`), with the desktop app unlocked and *Settings -> Developer -> Integrate with 1Password CLI* enabled
- **A Keeper account that signs in with SSO.** Master-password login is deliberately not supported.

## Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install '.[live]'
```

The `live` extra pins the Keeper SDK to an exact version. It reads a password
vault, so the version you audited should be the version you run.

## Use

Report only - writes nothing:

```bash
otp-backfill
```

Write, after showing you what it will do:

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

Interactive runs prompt for your Keeper address. Set `OTP_BACKFILL_EMAIL_DOMAIN`
and it will offer `<your-mac-username>@<that-domain>` as a default you can
overtype. Pass `--keeper-user` to skip the prompt entirely.

## What it cannot do

Enforced in code, not by policy:

- **It can't delete anything.** No delete call is ever constructed.
- **It never replaces an existing code.** An item that already has one is left alone and never opened.
- **It can't write to Keeper.** The SDK handle allows only `login`, `sync_down` and `communicate_rest`, held in a closure so the underlying module can't be reached around it - and `communicate_rest` is itself restricted to the logout endpoint, since it is otherwise a general REST call that could write.
- **It appends one field** and hands the rest of the item's fields, sections, urls and tags back untouched. `op item get --format=json` returns real values rather than concealment placeholders, so the round-trip returns the item's own password unchanged, and it refuses outright if it ever sees a placeholder. File attachments are not part of the item template and were not verified to survive the round-trip.

## The guard

Writing a seed to the wrong item is worse than not writing it. A missing code
shows up at the next sign-in and is still in Keeper; a wrong one attaches a
second factor to someone else's account, and the person it locks out isn't the
person who ran this. So ambiguity becomes a flagged line, never a guess.

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

### The cross-vault rule, and its precondition

Two same-titled items in two vaults are either one account shared into both, or
two different accounts that happen to share a title. Nothing 1Password knows
separates them; the only evidence that would is inside the items, which this tool
never reads. Guessing wrong writes a second factor into a vault with a different
audience, and it cannot take a field back once written.

Keeper does know one useful thing: which **shared folders** hold the record.

> **Precondition.** This assumes the migration created one 1Password vault per
> Keeper shared folder, so a vault the record was never in did not get its item
> from that record. If your import mapped folders to vaults differently, this
> corroboration is invalid and every cross-vault case should be treated as a
> refusal instead.

Given that, it can only ever *narrow*. If the record is in neither vault's
folder, or in both, or in none, the refusal stands. It is the *shared* folder
that counts, not the subfolder: a record in `Engineering > AWS` became an item in
the **Engineering** vault, so `AWS` corroborates nothing.

Within a single vault none of this is needed - same title and same username there
means one account duplicated by repeated imports, and the audience is identical
either way.

## How seeds are handled

Seeds are copied byte for byte. Nothing parses, validates or generates a code
from them, so whatever format Keeper holds survives.

A seed lives in a `Secret`, which renders as `<redacted>` in any string context,
refuses to pickle, and compares in constant time. The module unwraps one in
exactly one place.

A field is only read as a seed on strong evidence: an OTP field type, an OTP
label, or an `otpauth` prefix. Labels like "Secret Key" and "API Key" are
excluded.

**The seed never becomes a command argument.** `op` warns that arguments are
visible to other processes, so the item goes back through a JSON template on
**stdin** - never argv, never a file on disk. `scrub` strips secret-shaped text
from logs, errors and the report, including on the root logger where the vendor
SDK writes. It covers seeds in the spaced and hyphenated groups vendors display,
and hex seeds. It is the net under `Secret`, not the primary defence, and it
stops short of rules that would redact dates and ordinary words out of a report
you need to read.

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

They need no Keeper or 1Password access. Seeds in the fixtures are the public
RFC 6238 demo vectors.

## Status

Written for a one-time Keeper to 1Password migration, and focused on doing that
one job safely rather than growing features. Run it without `--apply` first, and
read what it reports, before letting it write anything.

## Licence

MIT - see [LICENSE](LICENSE).
