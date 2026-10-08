# Security policy

## Reporting a vulnerability

Please report security issues privately using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

This is a small personal project, so there is no formal response-time
commitment. Security reports are the one category that always gets looked at.

## Scope

`otp_backfill.py` is in scope. Reports about the matching guard writing a seed
to the wrong item, about a seed reaching `argv`, a log, an error message or
disk, or about the passkey check being bypassed are especially wanted.

## What this tool is trusted with

It reads TOTP seeds out of a Keeper vault and writes them into 1Password
items. A seed written to the wrong item attaches a second factor to somebody
else's account. The guard that prevents this, and the containment that keeps
seeds out of `argv` and off disk, are the two things most worth attacking.
