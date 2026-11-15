# Operations Guide (gateway on Kubernetes)

Runbooks for the platform team that runs `bastion3270-server`. The manifests are in
`deploy/k8s/`; the architecture and security model are in [ARCHITECTURE.md](ARCHITECTURE.md),
every setting in [CONFIGURATION.md](CONFIGURATION.md).

---

## 1. Before the first deployment

Fill in every `TODO` of `deploy/k8s/`:

| File | What |
| :--- | :--- |
| `kustomization.yaml` | The image and its tag: the published `ghcr.io/tom-danek/bastion3270-server`, or your mirror of it. |
| `gateway.yaml` | `gatewayClassName` of your Gateway API controller, the host name, the TLS Secret `bastion3270-tls` (type `kubernetes.io/tls`). With a shared platform Gateway: delete the Gateway and point the routes' `parentRefs` at it. |
| `configmap.yaml` | The profiles (one per LPAR / TN3270 server), `allowed_origins` (the public URL), `trusted_proxies` (§7), the authentication mode. Users may choose the terminal model, code page and LU name of a session; where the LU is a terminal identity on the host (RACF terminal rules, CICS terminal ids), restrict it per profile with `allowed_lu_names` (exact names or prefixes ending in `*`; `[]` allows none). |
| `networkpolicy.yaml` | The addresses of the TN3270 servers (one `/32` each; the example address reaches nothing) and the namespace / labels of your controller's proxy pods. |

**Connections users define themselves** (`[custom_connections]`) are enabled by default: a user
can then reach any host and port from the gateway's network position, and the gateway warns about
it at startup. For production, either switch them off (`enabled = false`) or restrict them:

```toml
[custom_connections]
allowed_targets = ["10.20.0.0/16:23,992", "*.zos.example.com:992"]  # hosts, *.domains, CIDR, :ports
allow_plain = false                                                  # TLS only
```

Names are matched as users type them (your DNS decides where they lead); address ranges match
only targets given as addresses. In Kubernetes the NetworkPolicy's egress rules limit the
reachable targets in any case. An identity whose token lists profiles needs the profile id
`custom` in that list to use custom connections. Every custom session is audited with the profile
id `custom:<host>:<port>`.

**The hosts' TLS certificates.** The gateway trusts the Mozilla roots; the container has no
system certificate store. If your TN3270 servers (AT-TLS) use your organisation's CA, put the CA
(and any intermediate a host does not send) in the Secret `bastion3270-zos-ca`, mount it
(commented out in `deployment.yaml`) and list it once for every profile and custom connection:

```toml
[host_tls]
ca_certs = ["/etc/bastion3270/pki/ca.crt"]
```

A profile's own `ca_cert` adds to these. If users connect by address or by an alias that the
certificate does not list, set `accept_hostname` in the profile to a name it does list. A
certificate with a common name only (no subject alternative names, as `RACDCERT GENCERT`
creates without `ALTNAME`) is checked by its common name. A refused certificate is audited with
the reason, issuer and SHA-256 (§8).

Validate the configuration before it reaches the cluster:

```bash
bastion3270-server --check-config bastion3270-server.toml
```

The namespace enforces the Pod Security Standard `restricted`; the gateway pod meets it
(non-root, read-only root filesystem, no capabilities, `RuntimeDefault` seccomp).

## 2. Deploy

```bash
kubectl apply -k deploy/k8s
kubectl -n bastion3270 rollout status deploy/bastion3270-server
kubectl -n bastion3270 get gateway,httproute          # Gateway PROGRAMMED=True
curl -sI https://<host>/healthz                        # 200, with Strict-Transport-Security
```

Then open `https://<host>/` in a browser and log on to one profile. The pod's log (JSON on
stdout) shows `bastion3270-server listening` and one warning per risky setting (e.g.
`auth.mode = "none"`, a profile with `tls_mode = "disabled"`).

Users can install the web client as an application from their browser (see the
[user guide](USER_GUIDE.md#install-the-web-client-as-an-application)). Chrome and Edge can
also install it for every managed workstation with the policy `WebAppInstallForceList`.

## 3. Change the configuration

The gateway reads its configuration at start only. A change needs a restart, and **a restart
ends every session** (users see "Session closed: server_shutdown" and log on again).

1. Edit `configmap.yaml`, run `--check-config` on the TOML.
2. Increase the annotation `bastion3270.io/config-revision` in `deployment.yaml` (or run
   `kubectl -n bastion3270 rollout restart deploy/bastion3270-server` after applying).
3. `kubectl apply -k deploy/k8s` and watch `rollout status`. An invalid configuration keeps
   the new pod from starting (`CrashLoopBackOff`, the reason is the last log line); fix it and
   apply again.

Do it outside working hours, or announce it: see §4 for what users experience.

## 4. Upgrade the gateway

Set the new image tag in `kustomization.yaml` and apply. The Deployment uses the `Recreate`
strategy (sessions live in the memory of one pod), so an upgrade replaces the pod:

1. Kubernetes sends `SIGTERM`. The gateway answers `/readyz` with 503, refuses new and resumed
   sessions (`shutting_down`), closes every session and waits until every browser has been told
   (`closed` with reason `server_shutdown`), at most 10 s, inside the 30 s grace period.
2. The new pod starts and becomes ready; users log on again.

In a test cluster with 50 active sessions the old pod was gone 0.4–1.1 s after `SIGTERM`
and the new one ready 0.7–1.2 s after the restart began; every browser was told. Plan the
upgrade like any change that ends user sessions. A session cannot be resumed on the new pod.

Roll back by setting the previous tag and applying again (same behaviour).

## 5. Rotate bearer tokens (`auth.mode = "static-token"`)

Only SHA-256 digests are stored in the configuration; the tokens themselves are never on the
server.

```bash
bastion3270-server --generate-token          # prints a new 256-bit token and its SHA-256
printf %s "$TOKEN" | bastion3270-server --hash-token   # digest of an existing token
```

1. Add an `[[auth.tokens]]` entry with the new digest (same `subject` and `profiles`), keep
   the old one; apply (§3).
2. Hand the new token to its user through your secret distribution; the user enters it at the
   next logon.
3. Remove the old entry; apply (§3). From now on the old token is rejected (audit
   `auth_failed`).

A suspected leak: remove the entry at once (step 3) and restart; every session of that
identity ends with the restart.

## 6. Monitoring

Prometheus metrics are served on `server.metrics_bind` (port 9090 in the example; the
NetworkPolicy admits the `monitoring` namespace). An example dashboard is in
`deploy/grafana/`.

| Metric | Watch for |
| :--- | :--- |
| `bastion3270_sessions{state}` | attached / detached sessions against `max_sessions`. |
| `bastion3270_sessions_opened_total{result}` | `result` other than `ok`: `connect_failed` (host or NetworkPolicy), `limit_exceeded`, `auth_failed`, `forbidden`. |
| `bastion3270_sessions_closed_total{reason}` | `host_error` / `host` (mainframe side), `idle`, `lifetime`, `shutdown`. |
| `bastion3270_host_connect_seconds` | slow TN3270 connects (network, TLS, host load). |
| `bastion3270_aid_response_seconds` | Enter → unlocked keyboard: the host's response time as users feel it. |
| `bastion3270_limit_rejections_total{limit}` | limits that refused something (connections, handshakes, message rate, sessions). |
| `bastion3270_websocket_connections` | open WebSockets. |

Audit records (logon, open, close with reason, AID with a digest of the masked screen, printed
screens) are
log lines with target `bastion3270::audit`; ship them to your SIEM. Screen contents and
passwords are never logged.

Sizing: about 16 MiB + 300 KiB per session and 0.13 CPU cores per 1 000 sessions at one Enter
every 2 s per session (0.15 with TLS on both sides). Set the memory limit for about 600 KiB
per session: after many sessions end and start again at once (session lifetime, host restart)
memory can stay near that for hours. See [ARCHITECTURE.md](ARCHITECTURE.md) §4.6.

## 7. Client addresses behind the Gateway

Without `trusted_proxies` the audit records the proxy pod's address for every user. To record
the browser's address:

* set `server.trusted_proxies` to the addresses of the proxy pods (their pod subnet). The
  NetworkPolicy admits only the proxies, so nothing else can reach the gateway with a forged
  `X-Forwarded-For`;
* make the controller's load balancer keep the client address (Service
  `externalTrafficPolicy: Local`, or your cloud's equivalent), otherwise the proxies see node
  addresses and pass those on;
* the proxy must set `X-Forwarded-Proto` itself; its last value is used for the same-origin
  check.

Clients inside the trusted range (e.g. a pod calling the Gateway through its ClusterIP) are not
recorded by address: their entry is skipped as a proxy.

## 8. Troubleshooting

| Symptom | Likely cause | What to do |
| :--- | :--- | :--- |
| Users get "could not connect to the host"; audit `connect_failed … timed out` | NetworkPolicy egress does not allow the TN3270 server, or the host is down | Check the `/32` and port in `networkpolicy.yaml`; test the host from a pod in another namespace. |
| `connect_failed … the host's certificate is issued by a certificate authority that is not trusted` | AT-TLS with an internal CA (the record names the issuer) | Mount the CA (or a missing intermediate) and list it in `[host_tls] ca_certs`, or `ca_cert` of the profile (§1). |
| `connect_failed … not issued for '<host>'` | Connecting by address or alias; the record lists the certificate's names | Use one of those names as `host`, or set `accept_hostname` in the profile. |
| `connect_failed … signed with an algorithm no longer accepted` | An old host certificate (e.g. SHA-1) | The host needs a new certificate (SHA-256 or stronger). |
| Browser: "origin not allowed" (HTTP 403), audit `policy_denied websocket origin not allowed` | `allowed_origins` does not contain the URL users open | Add the exact origin (`https://<host>`, with port if not 443). |
| "limit exceeded" | `max_sessions` / `max_sessions_per_identity` reached | Raise the limit (with memory, §6) or check for abandoned sessions. |
| Sessions end after 30 min | `idle_timeout_secs` (no operator input) | Intended (NIST SP 800-63B AAL2); adjust only with your security officer. |
| Every audit record shows the same address | `trusted_proxies` not set, or the load balancer hides the client | §7. |
| Gateway `PROGRAMMED=False` | The controller has no address for the Gateway (no load balancer) | Check the controller's Service; in a lab use `kubectl port-forward`. |
| Pod rejected: `violates PodSecurity "restricted"` | A changed securityContext | Restore the securityContext of `deployment.yaml`. |
| Pod `CrashLoopBackOff` after a change | Invalid configuration | `kubectl logs --previous`; validate with `--check-config`. |

More detail: `RUST_LOG=debug` in the Deployment's environment (logs host negotiation and
rejected records; still no screen contents).
