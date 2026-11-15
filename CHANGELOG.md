# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version
may contain breaking changes to the configuration or the WebSocket protocol; they are listed
under **Changed**.

## [0.1.0]

First public release.

### Protocol core (`bastion3270-core`)

* Telnet and TN3270E negotiation (RFC 854, RFC 1576, RFC 2355) including the BIND image and
  SSCP-LU mode; NVT text shown as a banner.
* 3270 data stream: commands, orders, extended attributes (colour, highlighting), structured
  fields and query replies; terminal models 2–5 and a dynamic screen size up to 62 × 160.
* All 35 single-byte host code pages of x3270 (e.g. CP037, CP1047, CP1140–CP1149, CP273,
  CP285, CP297, CP500, CP870), generated from its tables; APL / Graphic Escape characters.
* Keyboard and OIA state machine following x3270, including Dup, Field Mark and Erase Field;
  protected and numeric fields are enforced in the core.
* `SafeScreenView`: the content of non-display fields never leaves the core.

### Network layer (`bastion3270-net`)

* Asynchronous TCP and TLS 1.2 / 1.3 (`rustls`); certificate verification always on, with
  the Mozilla roots, the operating system's certificate store and your own CAs; a certificate
  without subject alternative names is checked by its common name, as x3270 does
  (`accept_hostname` for a different name); client certificates (mutual TLS).
* A refused certificate is reported with the reason, issuer, validity, names and SHA-256.
* Connection profiles in TOML; a deadline for every step of a session.

### Web gateway (`bastion3270-server`)

* The 3270 session runs in the gateway; the browser receives only the masked screen
  (WebSocket protocol `bastion3270.v1`).
* Profiles defined by the administrator, with per-profile copy, paste and print policy, LU
  names (`allowed_lu_names`) and the default keyboard layout; session choices (model, screen
  size, code page, LU name) validated before anything connects.
* Connections users define themselves (`[custom_connections]`), restricted to
  `allowed_targets`, to TLS, or switched off by the administrator.
* Sessions survive a page reload or a network drop; closed after inactivity, after a maximum
  lifetime or when the sign-in expires, and the browser is told why.
* Optional bearer-token authentication; limits against denial of service; structured audit
  log; Prometheus metrics; `/healthz` and `/readyz`; optional HTTPS listener with client
  certificates; graceful shutdown.
* A minimal non-root container image; Kubernetes manifests on Gateway API; an example Grafana
  dashboard.

### Web client

* Several sessions in tabs; message line in plain language (English and Czech); automatic
  reconnect.
* The screen fits the window; zoom; full screen; crisp text on HiDPI displays.
* Keyboard layouts of x3270 and IBM Personal Communications; key help.
* Colour themes, cursor shape, crosshair, key bar; copy, paste and print following each
  profile's policy.
* Can be installed as an application from the browser.

### Desktop client (`bastion3270-gui`)

* For Linux, Windows and macOS; the same keyboard layouts and colour themes as the web client.
* Profile manager with Save and Cancel; profiles in the per-user configuration directory or a
  file given with `--profiles`.
* A refused host certificate can be trusted for its profile after comparing its fingerprint.
* Mouse selection, copy and paste; diagnostics log.

### Releases

* Desktop archives for Linux (x86_64), Windows (x86_64) and macOS (Apple Silicon) with
  `SHA256SUMS`, the third-party licence texts and a CycloneDX SBOM per platform.

[0.1.0]: https://github.com/tom-danek/bastion3270/releases/tag/v0.1.0
