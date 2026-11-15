# Security Policy

`bastion3270` sits between users and mainframe applications that handle sensitive data, so
security reports are welcome and handled with priority.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/tom-danek/bastion3270/security/advisories/new)
(repository → *Security* → *Advisories* → *Report a vulnerability*).

Please include:

* the affected component (web gateway, web client, desktop client, protocol core) and version
  or commit;
* the configuration involved (with secrets, host names and addresses removed);
* steps to reproduce, or a proof of concept;
* the impact you expect (e.g. hidden field content disclosed, session takeover, denial of
  service).

Do not include real screen contents, user ids, passwords or host names of a production system.
If a trace of host traffic is needed, we will agree on a way to share a redacted one.

## What to expect

* An acknowledgement within **7 days**.
* An assessment (accepted / not a vulnerability / needs more information) within **14 days**.
* A fix released as soon as practical, depending on severity, and a GitHub security advisory
  (with a CVE where appropriate) crediting the reporter unless they prefer otherwise.
* Coordinated disclosure: please give us up to **90 days** from the report before publishing
  details. We will agree on an earlier date once a fix is available.

## Supported versions

The project is pre-1.0. Security fixes are made on `main` and shipped in the next release;
older releases are not patched.

| Version | Supported |
| :--- | :--- |
| latest release | yes |
| older releases | no |

## Scope

In scope:

* `bastion3270-server` (web gateway) and the web client it serves;
* `bastion3270-gui` (desktop client);
* `bastion3270-core` and `bastion3270-net` (protocol, TLS transport, session handling);
* the container image and the example deployment manifests in `deploy/`, where a default makes
  an installation insecure.

Of particular interest: content of non-display (hidden) fields leaving the protocol core, input
accepted into protected fields, cross-site WebSocket hijacking, session resume or takeover,
connections to hosts other than the configured ones (SSRF), memory or CPU exhaustion from a
single client or host, and secrets in logs.

Out of scope: vulnerabilities in the mainframe or its TN3270 server, in Hercules or other
emulators, and findings that need an operator to disable a documented security default (e.g.
`tls_mode = "disabled"` for a lab host).

The security model is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (§2 and §4).
