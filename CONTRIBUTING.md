# Contributing

This was written for a one-time migration and is deliberately narrow in scope.
Please set expectations accordingly:

- **Security reports** - see [SECURITY.md](SECURITY.md). These get attention.
- **Bug reports** - welcome, especially with a reproduction. They may sit.
- **Feature requests** - considered, but the bar is high: this does one job and a wider surface means more ways to write the wrong thing.
- **Pull requests** - happily reviewed. Keep them focused, and explain the
  behaviour change in the description rather than only in code.

Run the tests before opening a PR, and say in the description how the change was
verified beyond them.

## Style

Match what is already there: explain *why* in comments, not *what*. The code
handles credentials, so a change that weakens a guard needs to argue for itself.
