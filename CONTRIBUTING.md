# Contributing

Thank you for your interest in `bastion3270`.

## Current status

**Issues are welcome; pull requests are not accepted yet.** The contribution terms are still
being prepared. Until they are published, pull requests will be closed without review, however
small — please open an issue instead and describe the change you have in mind.

Security problems are reported privately, never in an issue — see [SECURITY.md](SECURITY.md).

## Reporting a bug

Use the *Bug report* issue template and include:

* the component (web gateway, web client, desktop client) and the version or commit;
* the host side: z/OS (with the TN3270 server, e.g. z/OS Communications Server), Hercules, or
  another emulator; TN3270 or TN3270E; terminal model and code page;
* what you did, what you expected and what happened;
* the relevant log lines, at `RUST_LOG=debug` if possible.

**Never post screen contents, user ids, passwords, host names or IP addresses of a real
system.** Logs of `bastion3270` do not contain field contents, but check them before posting.
If a protocol trace is needed to reproduce a problem, say so in the issue and we will agree on
how to share a redacted one.

## Proposing a feature

Use the *Feature request* issue template. Describe the problem first (what you need to do on
the mainframe and why the current behaviour does not allow it), then the solution you
suggest. If the behaviour exists in another 3270 emulator (e.g. x3270 / wc3270), name it —
`bastion3270` follows x3270's behaviour wherever possible.

## Building and testing

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the toolchain, the engineering standards
(no `unsafe`, no panics in production code, typed errors), a local Hercules mainframe and the
test suites. The architecture and the security model are described in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
