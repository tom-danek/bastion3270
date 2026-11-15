# Development Guide

## 1. Toolchain

Use **`rustup`** with the stable toolchain (not a distribution `rust` package), so additional
targets such as `x86_64-pc-windows-gnu` can be added without root. The oldest supported Rust
release is the `rust-version` in `Cargo.toml` (1.99). Containers are built with
`podman` (or `docker`).

```bash
cargo check                                   # fastest type check of the workspace
cargo test                                    # unit, integration and hermetic E2E tests
cargo test -p bastion3270-core                   # one crate
cargo clippy --all-targets -- -D warnings     # lints (must be clean)
cargo fmt --all                               # formatting
```

**Definition of done for every change:** `cargo fmt --all --check`, `cargo clippy --all-targets --
-D warnings` and `cargo test` pass; every bug fix comes with a regression test that reproduces the
real-world scenario.

---

## 2. Engineering standards

`bastion3270` targets mission-critical corporate environments (banking, insurance, public
administration), where one gateway process serves many sessions. A corrupted packet or hostile
input in one session must never take down the process or leak data.

### 2.1 Zero-panic and memory safety (enforced in `Cargo.toml`)
* `unsafe_code = "forbid"` — no `unsafe` anywhere.
* `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` = `deny` — fallible operations
  return a typed `Result<T, Error>`.
* `indexing_slicing = "deny"` — no unchecked `buf[i]` / `&data[a..b]`; use `.get()`.
* Tests may opt out locally with `#[allow(clippy::unwrap_used, ...)]`; production code may not.

### 2.2 Resource governance (DoS)
* All network and browser input is untrusted. Frames, messages and pastes have hard size limits;
  an endless stream without `IAC EOR` terminates the session instead of allocating memory.
* Inter-task communication uses bounded channels only (backpressure).
* Every network operation has a timeout (connect, TLS handshake, negotiation, idle).

### 2.3 Sensitive data
* `Non-display` field content never leaves `bastion3270-core` in readable form — not to clients, logs
  or extensions.
* Sensitive buffers are zeroised when the screen is erased or the session ends; secrets use a
  `Secret` type with a redacted `Debug`.
* Logs never contain screen content or credentials.

### 2.4 Protocol behaviour
* Behaviour follows `x3270` and the RFCs / IBM documentation; cite the reference function or
  section in doc comments.
* Defects are fixed at their root cause in the layer where they belong (protocol in
  `bastion3270-core`, I/O in `bastion3270-net`, presentation in the clients).
* Unsupported input is skipped or rejected explicitly (typed error or `warn!` without sensitive
  data) — never in a way that silently hangs a session.

---

## 3. Local mainframe: Hercules MVS 3.8j (TK4-)

```bash
# the image of docker/docker-compose.yml (pinned to its digest there)
podman run -d --replace --name bastion3270-hercules --platform linux/amd64 \
  -p 127.0.0.1:3270:3270 -p 127.0.0.1:8038:8038 \
  docker.io/rattydave/docker-ubuntu-hercules-mvs@sha256:13b053388b37a10812d00316659b5faa36939d44b78197dd86f6e4cdc20fde2a
podman logs -f bastion3270-hercules          # MVS IPL takes about a minute
```

* `--replace` removes an existing container of the same name (e.g. a stopped one from an earlier
  run) and creates a fresh one; without it Podman refuses with "name is already in use". To keep
  the previous container's state instead, use `podman start bastion3270-hercules`.
* TN3270: `127.0.0.1:3270`; Hercules web console: `http://127.0.0.1:8038`.
* The first connection to a terminal after the IPL shows only the TK4- logo: press **Clear**
  (as the TK4- manual says) and the logon screen appears.
* Default TK4- TSO users (public defaults of the TK4- distribution, local emulator only):
  `HERC01` / `CUL8TR`, `HERC02` / `CUL8TR`, `HERC03` / `PASS4U`.
* Hercules + the published gateway image: `podman-compose -f docker/docker-compose.yml up -d`;
  with the gateway built from this checkout instead:
  `podman-compose -f docker/docker-compose.yml -f docker/docker-compose.build.yml up -d --build`.

---

## 4. `x3270` reference sources

The port is written against the `x3270` sources (BSD-3-Clause), kept outside Git history:

```bash
git clone https://github.com/pmattes/x3270.git vendor/x3270-ref   # vendor/x3270-ref/ is git-ignored
```

Most relevant files in `vendor/x3270-ref/Common/`: `ctlr.c` (3270 controller: commands, orders,
read buffer / read modified), `sf.c` (structured fields, query replies), `telnet.c` (Telnet /
TN3270E), `kybd.c` (keyboard), `unicode.c` and `tables.c` (code pages).

The EBCDIC code page tables of `bastion3270-core` (`src/ebcdic/tables.rs`: every single-byte
host code page of x3270 with its aliases) are generated from `unicode.c`; do not edit them by
hand:

```bash
python3 -I tools/gen-codepages.py vendor/x3270-ref/Common/unicode.c \
    > crates/bastion3270-core/src/ebcdic/tables.rs && cargo fmt
cargo test -p bastion3270-core --test codepages    # round trips and spot checks
```

---

## 5. Web gateway `bastion3270-server`

### Run from `cargo`

```bash
# docker/bastion3270-server.toml uses host "hercules" (compose network); point it at localhost
sed 's/^host = "hercules"/host = "127.0.0.1"/' docker/bastion3270-server.toml > /tmp/bastion3270-dev.toml
cargo run -p bastion3270-server -- --config /tmp/bastion3270-dev.toml   # → http://127.0.0.1:8080
```

### Run in a container

```bash
podman build -f docker/Dockerfile.server -t localhost/bastion3270-server:dev .
```

### Binary flags

```bash
bastion3270-server --check-config docker/bastion3270-server.toml   # validate configuration
bastion3270-server --generate-token                             # new 256-bit token + its SHA-256
printf %s "$TOKEN" | bastion3270-server --hash-token            # SHA-256 for [[auth.tokens]] (>= 32 chars)
bastion3270-server --healthcheck 127.0.0.1:8080                 # container HEALTHCHECK without curl
RUST_LOG=debug BASTION3270_LOG_FORMAT=json bastion3270-server ...  # JSON logs (audit target: bastion3270::audit)
```

### Gateway tests

```bash
cargo test -p bastion3270-server                                                  # hermetic (mock host)
cargo test -p bastion3270-server --test gateway_live -- --ignored --nocapture     # live against Hercules
BASTION3270_GATEWAY_ADDR=127.0.0.1:8080 \
  cargo test -p bastion3270-server --test gateway_live -- --ignored --nocapture   # against a running gateway
```

### Web client tests

The browser client (`crates/bastion3270-server/web/`) is plain JavaScript without a build step:
`app.js` wires the page, `keymap.js` and `screen.js` are pure ES modules. It is tested in real
browsers over WebDriver from Rust (`tests/web_client_tests.rs`): each test runs the gateway and a
mock host in-process, so it checks the whole path from a key press in the browser to the bytes
the host receives. The pure modules are imported and called in the browser itself.

The tests are ignored by default because they need a browser and its WebDriver server:

```bash
# Chromium (chromedriver ships with it), Firefox with geckodriver, or Edge with msedgedriver
chromedriver --port=9515 &
cargo test -p bastion3270-server --test web_client_tests -- --ignored

geckodriver --port 4444 &
BASTION3270_WEBDRIVER=firefox cargo test -p bastion3270-server --test web_client_tests -- --ignored
```

`BASTION3270_WEBDRIVER` selects `chrome` (default), `firefox` or `edge`;
`BASTION3270_WEBDRIVER_URL` overrides the WebDriver address. The browsers run headless.

### Recorded host traffic

Host data streams contain what an emulator such as Hercules never sends (structured field
queries, Outbound 3270DS, box drawing). With access to a host, `bastion3270-net` records a
session through a proxy and replays it in tests. Recordings contain host screens and account
details: keep them outside the repository.

```bash
# record: point a client profile at 127.0.0.1:3271, use the terminal, stop with Ctrl+C
cargo run -p bastion3270-net --example record_proxy -- record --listen 127.0.0.1:3271 \
  --target <host:port> --out <dir>/traces/logon.trc --model Model4 --redact USER01=XXXXXX
cargo run -p bastion3270-net --example record_proxy -- dump <dir>/traces/logon.trc   # review

# replay every trace of <dir> (core) and traces/logon.trc (whole session stack)
BASTION3270_HOST_CORPUS=<dir> cargo test -p bastion3270-net --test recorded_host_replay -- --ignored
BASTION3270_UPDATE_GOLDEN=1 ...   # rewrite <dir>/golden/*.txt, then review the change
```

What the client sends is redacted while recording: typed field contents and passwords never
reach the trace, only the record structure (AID, cursor, buffer addresses, structured field
replies). The hermetic tests of the same file record a scripted session and replay it, so the
tooling is tested without any recording.

### Metrics, benchmarks and load tests

```bash
# metrics: set [server] metrics_bind = "127.0.0.1:9090", then
curl -s 127.0.0.1:9090/metrics

# benchmarks of the hot paths (data stream, projection, frame encoding)
cargo bench -p bastion3270-core -p bastion3270-server -- --save-baseline main
cargo bench -p bastion3270-core -p bastion3270-server -- --baseline main     # compare later

# load test: simulated hosts, a gateway (release build) configured for them, simulated browsers
cargo build --release -p bastion3270-server -p bastion3270-loadgen
target/release/bastion3270-loadgen host --listen 127.0.0.1:13270 --delay-ms 20 &
target/release/bastion3270-loadgen config --host 127.0.0.1:13270 --sessions 1000 \
  --bind 127.0.0.1:18080 --metrics 127.0.0.1:19090 > /tmp/load.toml
target/release/bastion3270-server --config /tmp/load.toml &
target/release/bastion3270-loadgen run --gateway 127.0.0.1:18080 --sessions 1000 \
  --ramp-s 30 --duration-s 60 --think-ms 2000 --gateway-pid $!
```

`run` reports opened and failed sessions and Enter → screen latency percentiles, and with
`--gateway-pid` the gateway's memory, CPU and file descriptors. A long `--duration-s` is a soak
test. Each session needs two file descriptors in each process (`ulimit -n`). Sessions the
gateway ends are listed by its reason (`ended={…}`). The gateway ends every session after
`limits.max_session_lifetime_secs` (12 h by default); a longer soak needs `--reopen`, which
opens an ended session again.

---

## 6. Property tests, fuzzing and supply chain

**Property tests** (`proptest`, stable) run as part of `cargo test`. They check invariants on
arbitrary input: Telnet parsing gives the same result however the input is split into network
chunks, the data stream parser keeps cursor and buffer address on the screen, non-display fields
are always masked in `SafeScreenView`, and the keyboard never panics or exceeds its typeahead
bound.

```bash
cargo test -p bastion3270-core --test properties                    # 256 cases per property
PROPTEST_CASES=5000 cargo test -p bastion3270-core --test properties   # longer run
```

**Fuzzing** (`cargo-fuzz` / libFuzzer) lives in `fuzz/`, a separate workspace. libFuzzer's
coverage instrumentation needs the nightly toolchain (`-Z sanitizer`); the product itself is built
with stable only.

```bash
rustup toolchain install nightly && cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz list                     # telnet_inbound, datastream, keyboard, ...
mkdir -p corpus/datastream
cargo +nightly fuzz run datastream corpus/datastream seeds/datastream -- -max_total_time=600
cargo +nightly fuzz run datastream artifacts/datastream/crash-...   # replay a finding
./campaign.sh 3600       # every target in parallel for an hour, then minimise the corpus
```

The committed seed inputs are in `fuzz/seeds/<target>/`. libFuzzer writes the inputs it finds to
the first directory, `fuzz/corpus/<target>/`, which is ignored by Git, so a long run does not
touch the seeds.

Every finding is fixed at its root cause and gets a regression test that replays the exact input.

**Supply chain:** `cargo deny check` (advisories, licences, sources, duplicates; policy in
`deny.toml`) and `cargo audit` (exceptions in `.cargo/audit.toml`, kept in sync with `deny.toml`).
The release workflow adds the licence texts of every third-party crate to each archive
(`THIRD_PARTY_LICENSES`, cargo-about with `about.toml` / `about.hbs`; its accepted licences
mirror `deny.toml`) and a CycloneDX SBOM per platform. Locally:

```bash
cargo install --locked cargo-about --version 0.9.3 --features cli
cargo install --locked cargo-cyclonedx --version 0.5.9
cargo about generate -m crates/bastion3270-gui/Cargo.toml about.hbs -o /tmp/THIRD_PARTY_LICENSES
cargo cyclonedx -f json --spec-version 1.5 --describe binaries --no-build-deps \
    --target x86_64-unknown-linux-gnu --manifest-path crates/bastion3270-gui/Cargo.toml
```

**CI** (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request that
changes more than documentation: format, clippy, tests, `cargo deny` and the web client tests in
Chrome and Firefox; the tests of the desktop client's crates on Windows and macOS; and a build
with the oldest supported Rust (the `rust-version` in `Cargo.toml`). Weekly it checks the
security advisories and runs every fuzz target for 60 seconds. Started by hand (Actions → ci →
Run workflow, e.g. before a release) it also runs the web client tests in Edge and the fuzz
targets. Long fuzzing campaigns (`fuzz/campaign.sh`) run locally. The container image is built
and started with the example configuration by `.github/workflows/container.yml` whenever the
Dockerfile, `.dockerignore` or `Cargo.lock` changes. Actions are pinned to commit SHAs, the
workflow token is read-only and every job has a time limit.

**Releases** (`.github/workflows/release.yml`) are built only from a version tag, never from a
normal push. The tag must match the workspace version in `Cargo.toml`:

```bash
git tag -a v0.1.0 -m "bastion3270 0.1.0"
git push origin v0.1.0
```

The desktop client is built and tested on native runners for Linux (x86_64, `.tar.gz`), Windows
(x86_64, `.zip`) and macOS (Apple Silicon, `bastion3270.app` in a `.zip`), without a build cache.
The gateway is built by its container build on a native runner per architecture (x86_64, arm64):
the `binary` stage of `docker/Dockerfile.server` becomes the release archive, and on a tag the
same build is pushed to `ghcr.io/tom-danek/bastion3270-server` with an SBOM and build
provenance, joined into one image under the version and `latest`. The archives, the SBOMs and
`SHA256SUMS` are attached to a draft release, which is published by hand. Every asset and the
image get a signed build provenance attestation (GitHub artifact attestations, Sigstore):

```bash
gh attestation verify bastion3270-server-vX.Y.Z-linux-x86_64.tar.gz --repo tom-danek/bastion3270
gh attestation verify oci://ghcr.io/tom-danek/bastion3270-server:X.Y.Z --repo tom-danek/bastion3270
```

The binaries are not code-signed with a trusted identity yet. On macOS the first start is
refused; allow it in System Settings → Privacy & Security → Open Anyway, or remove the download
flag with `xattr -dr com.apple.quarantine bastion3270.app`. Windows SmartScreen asks too (More
info → Run anyway). Started by hand (Actions → release → Run workflow), the workflow is a dry
run: it builds the archives and keeps them as workflow artifacts, and it creates no release.
