# Configuration Reference

Every setting of the gateway (`bastion3270-server`) and of the desktop client
(`bastion3270-gui`). Both use TOML; **unknown keys are rejected**, so a typo stops the start
instead of being ignored. How to run and change the gateway in Kubernetes is in
[OPERATIONS.md](OPERATIONS.md); a commented example is `docker/bastion3270-server.toml`.

Check a gateway configuration before you deploy it:

```bash
bastion3270-server --check-config bastion3270-server.toml
```

It loads every certificate file the configuration names and prints one warning per risky
setting (the same warnings the gateway logs at startup).

---

## 1. Gateway file (`bastion3270-server.toml`)

The gateway reads `/etc/bastion3270/bastion3270-server.toml`, another path given with
`--config PATH`, or the path in `BASTION3270_SERVER_CONFIG`. It reads the file at start
only; a change needs a restart.

| Section | Purpose |
| :--- | :--- |
| [`[server]`](#11-server) | Listener, origins, proxies, metrics, HTTPS |
| [`[limits]`](#12-limits) | Capacity, timeouts, denial-of-service limits |
| [`[auth]`](#13-auth) | Gateway authentication |
| [`[host_tls]`](#14-host_tls) | Trusted CAs for the hosts' certificates |
| [`[custom_connections]`](#15-custom_connections) | Connections users define themselves |
| [`[[profiles]]`](#16-profiles) | The mainframe targets users pick from (at least one) |

### 1.1 `[server]`

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `bind` | `"0.0.0.0:8080"` | Address and port of the HTTP / WebSocket listener. |
| `allowed_origins` | `[]` | Browser origins allowed to open a WebSocket (`"https://tn3270.example.com"`, with the port if not 443). Empty: the same origin as the page only. |
| `trusted_proxies` | `[]` | Address ranges (CIDR) of reverse proxies whose `X-Forwarded-For` / `X-Forwarded-Proto` are believed (the audit then records the browser's address). Empty: the headers are ignored. |
| `metrics_bind` | unset | Address of a separate listener for Prometheus metrics (`GET /metrics`). Unset: no metrics. |

**`[server.tls]`** — serve HTTPS / WSS instead of HTTP (e.g. an encrypted hop from the
ingress to the pod):

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `cert` | required | PEM file: the server certificate, then its intermediates. |
| `key` | required | PEM file: the private key of `cert`. |
| `client_ca` | unset | PEM file with CAs; when set, every client must present a certificate signed by one of them (mutual TLS). |

### 1.2 `[limits]`

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `max_sessions` | `500` | Mainframe sessions of this gateway process (pod). |
| `max_sessions_per_identity` | `4` | Sessions of one authenticated identity (not applied with `auth.mode = "none"`, where everyone shares one identity). |
| `max_tabs_per_page` | `4` | Session tabs the web client offers in one page (1–16). |
| `detach_grace_secs` | `300` | How long a session survives without a browser (reload, network drop) before it is closed. |
| `idle_timeout_secs` | `1800` | A session without operator input for this long is closed, even with a browser attached. |
| `max_session_lifetime_secs` | `43200` | Longest life of a session, however active (12 h). |
| `reaper_interval_secs` | `15` | How often expired sessions are looked for. |
| `max_connections` | `1024` | HTTP connections that are not (yet) a WebSocket (1–1 000 000). |
| `max_pending_handshakes` | `64` | WebSockets waiting for their first message (1–1 000 000). |
| `header_read_timeout_secs` | `10` | Time to send a complete HTTP request head (slow-client protection). |
| `ping_interval_secs` | `25` | WebSocket ping interval; a browser silent for two intervals is detached. |
| `max_ws_message_bytes` | `16384` | Largest WebSocket message from a browser (at least 256). |
| `max_paste_chars` | `2048` | Longest paste. |
| `max_messages_per_second` | `200` | Messages per second and connection (flood protection). |

All values must be greater than zero. Sizing: about 16 MiB plus 300 KiB per session and
0.13 CPU cores per 1 000 sessions; set memory limits for about 600 KiB per session (see
[ARCHITECTURE.md](ARCHITECTURE.md) §4.6).

### 1.3 `[auth]`

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `mode` | `"none"` | `"none"`: no gateway logon, users log on at the mainframe screen (warned at startup). `"static-token"`: every user presents a bearer token. |

**`[[auth.tokens]]`** — one entry per token (`mode = "static-token"` needs at least one):

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `subject` | required | Name of the identity in the audit records. |
| `sha256` | required | SHA-256 of the token, 64 hex digits. The token itself is never stored. |
| `profiles` | `[]` | Profile ids this token may open; empty: all. Custom connections need the id `custom` in a non-empty list. |

```bash
bastion3270-server --generate-token                     # a new token and its SHA-256
printf %s "$TOKEN" | bastion3270-server --hash-token    # the SHA-256 of an existing token
```

### 1.4 `[host_tls]`

Which certificates of TLS hosts are trusted. The Mozilla roots and the operating system's
store are always trusted (the container image has no system store of its own).

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `ca_certs` | `[]` | CA certificate files (PEM or DER) trusted for every profile and every custom connection: your organisation's CA, or an intermediate a host does not send. |

### 1.5 `[custom_connections]`

Lets users connect to a host, port and TLS setting of their own ("New connection" on the start
screen). **Enabled by default, and then any host and port the gateway can reach** (warned at
startup): restrict or disable it in production.

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `enabled` | `true` | Offer custom connections at all. |
| `allowed_targets` | unset | Targets users may connect to. Unset: any. Entries: `host`, `*.domain`, an IP address, a CIDR range or `*`, each optionally with `:port` or `:port,port` (`["10.20.0.0/16:23,992", "*.zos.example.com:992"]`). Names match as typed; ranges match only addresses. |
| `allow_plain` | `true` | Allow connections without TLS. |
| `allow_paste` | `true` | Paste into custom sessions. |
| `allow_copy` | `true` | Copy and print in custom sessions. |

Custom sessions are audited with the profile id `custom:<host>:<port>`.

### 1.6 `[[profiles]]`

One entry per mainframe target; users pick them on the start screen.

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `id` | required | Short stable id (`[a-z0-9_-]`, 1–64 characters, unique; `custom` is reserved). |
| `name` | required | Name shown to users. |
| `description` | `""` | Shown under the name. |
| `allow_paste` | `true` | Users may paste into the session. |
| `allow_copy` | `true` | Users may copy the screen and print it. |
| `keyboard` | `"x3270"` | Default key layout of the web client: `"x3270"` or `"pcomm"` (IBM Personal Communications); each user may switch. |
| `allowed_lu_names` | unset | LU names users may request: exact names or prefixes ending in `*` (`["TSO0*", "CICS01"]`). Unset: any valid LU name; `[]`: none. |

**`[profiles.connection]`** — the connection, never shown to the browser. Same keys as a
desktop profile's `[profiles.connection]` (§2), except that `pinned_cert_sha256` is refused:
in the gateway only the administrator's CAs decide which certificates are trusted.

**What users may choose per session.** On the start screen a user may pick, for one session,
the terminal model or a dynamic size between 24 × 80 and 62 × 160, the code page and an LU name
(within `allowed_lu_names`). The gateway validates every choice; host, port, TLS and the
policies above are never the user's.

### 1.7 Environment

| Variable | Meaning |
| :--- | :--- |
| `BASTION3270_SERVER_CONFIG` | Path of the configuration file. |
| `BASTION3270_SERVER_BIND` | Overrides `server.bind`. |
| `BASTION3270_LOG_FORMAT` | `json` for JSON log lines (one per line, for log collectors). |
| `RUST_LOG` | Log level (`info` default; `debug` adds the host negotiation, never screen contents). |

---

## 2. Connection settings (`connection`)

Shared by gateway profiles (`[profiles.connection]`) and desktop profiles.

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `host` | `"127.0.0.1"` | Host name or IP address of the TN3270 server. |
| `port` | `3270` | TCP port (often 23 plain, 992 with TLS). |
| `tls_mode` | **required** | `"enabled"` (TLS 1.2 / 1.3) or `"disabled"` (clear text, warned). No default, so a forgotten setting never sends passwords in clear text. |
| `ca_cert` | unset | A CA file (PEM or DER) trusted in addition to the Mozilla roots, the system store and the gateway's `ca_certs`. TLS only. |
| `accept_hostname` | unset | The name the host's certificate must match instead of `host` (a DNS name or IP address), e.g. when connecting by address to a certificate for a host name. TLS only. |
| `pinned_cert_sha256` | unset | Desktop only: SHA-256 (64 hex digits) of one host certificate trusted as it is. Set by the client's trust dialog. TLS only. |
| `client_cert` | unset | PEM file: the client certificate (and intermediates) presented to the host (mutual TLS, e.g. AT-TLS with client authentication). Needs `client_key` and TLS. |
| `client_key` | unset | PEM file: the private key of `client_cert`. |
| `lu_name` | unset | LU name or LU pool requested from the host: 1–8 of `A–Z 0–9 @ # $`, not starting with a digit. Unset: the host assigns one. |
| `terminal_model` | `"Model2"` | `"Model2"` (24 × 80), `"Model3"` (32 × 80), `"Model4"` (43 × 80), `"Model5"` (27 × 132) or `"dynamic:ROWSxCOLS"` (e.g. `"dynamic:62x160"`, needs `extended = true`). |
| `color_3279` | `true` | Colour terminal (3279) instead of monochrome (3278). |
| `extended` | `true` | Extended data stream (colours, highlighting, query replies). |
| `codepage` | `"cp037"` | Host code page: any single-byte code page of x3270 by name, number or alias (`cp037`, `cp1047`, `cp1140`–`cp1149`, `cp273`, `cp285`, `cp297`, `cp500`, `cp870`, …). |
| `numeric_lock` | `false` | Only digits, `+ - . ,` may be typed into numeric fields (x3270 `numericLock`); off: the host checks them. |
| `blank_fill` | `true` | Typing after empty positions of a field turns them into spaces (x3270 `blankFill`). |
| `connect_timeout_ms` | `10000` | TCP connect and TLS handshake. |
| `negotiation_timeout_ms` | `30000` | From connect until the Telnet negotiation is complete. |
| `idle_timeout_ms` | `60000` | Host silence before the connection counts as dead; set it above the host's own idle logoff (e.g. `1800000` for TSO). |
| `write_timeout_ms` | `30000` | One write to the host; a host that stops reading ends the session. |
| `channel_capacity` | `128` | Internal queue length per session (1–4096); rarely changed. |

**Host certificates.** A certificate is trusted if its chain leads to the Mozilla roots, the
operating system's store, the gateway's `[host_tls] ca_certs` or the profile's `ca_cert`. Its
name must match `accept_hostname` or `host`; a certificate without subject alternative names
is matched by its common name, as x3270 does (z/OS certificates created without `ALTNAME`).
A refused certificate is reported with the reason, issuer, validity, names and SHA-256.

---

## 3. Desktop client profiles

The desktop client keeps its profiles in `profiles.toml` in the per-user configuration
directory (Linux `~/.config/bastion3270/`, Windows `%APPDATA%\bastion3270\`, macOS
`~/Library/Application Support/bastion3270/`); Help → About shows the path. Another file can
be given with `--profiles <file>`.

The profile manager (**Profiles…** in the toolbar or the Session menu) opens in a window of
its own: the list of profiles on the left, the settings of the chosen one on the right.
**Save** writes all changes, **Cancel** drops them. The profile chosen there for editing is
independent of the profile the main window connects with. Settings changed in the View menu
are stored in the current profile at once.

The file format is for import, export and distribution:

```toml
selected_index = 0

[[profiles]]
name = "z/OS production"
description = "LPAR PROD1, AT-TLS"
color_scheme = "classic3279"
cursor_style = "block"
crosshair_enabled = false
highlight_input_fields = false
keyboard = "pcomm"

[profiles.connection]
host = "zos1.bank.example"
port = 992
tls_mode = "enabled"
terminal_model = "Model4"
codepage = "cp870"
```

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `name` | required | Name in the session selector. |
| `description` | `""` | Notes. |
| `color_scheme` | `"classic3279"` | `"classic3279"`, `"light"`, `"green-phosphor3278"` or `"amber-phosphor"`. |
| `cursor_style` | `"block"` | `"block"`, `"underscore"` or `"vertical-bar"`. |
| `crosshair_enabled` | `false` | Crosshair lines through the cursor. |
| `highlight_input_fields` | `false` | Mark the input fields. |
| `keyboard` | `"x3270"` | `"x3270"` or `"pcomm"`, as in the web client. |
| `connection` | | The connection settings of §2. |

A file that cannot be read is kept aside as `profiles.toml.invalid-<time>` and the client
starts with the built-in profiles, so no settings are lost silently.
