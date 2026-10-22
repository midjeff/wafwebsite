# Assignment 1 — Web attacks, ModSecurity and OWASP CRS

## Scope and evidence status

This is an intentionally vulnerable, local-only training portal with synthetic employees, tickets and documents. The six scenarios cover five vulnerability classes: SQL injection, XSS (reflected and stored), OS command injection, path traversal and IDOR. No external target was tested.

Updated 22 October 2026 (Asia/Qyzylorda). Docker and all three application/WAF containers are running. The full `scripts/lab.ps1 test` passed **72/72 HTTP checks, 10/10 correlated CRS audit checks and all three bounded brute-force scenarios**. Loopback ping passed in both app containers as UID/GID 10001; structural verification passed 61/61. Headless Chrome passed 25/25 browser checks. SonarQube analyzed vulnerable and fixed separately; exports and quality gates are in `TASK-2-SAST.md`.

Current evidence: `generated/http-vulnerable.json`, `generated/http-waf.json`, `generated/http-fixed.json`, `generated/waf-evidence.json`, `generated/ping-runtime.json`, `logs/waf.log`. Earlier Windows results (26 local and 36 HTTP checks) remain in `generated/local-checks.json` and `generated/local-http/`; they were not rerun. SonarQube remains NOT RUN.

## Architecture

```text
127.0.0.1:8080 ───────────────────────────► vulnerable Flask :5000
                                                │
127.0.0.1:8081 ─► nginx + ModSecurity + CRS ───────┘
                                                └── vulnerable_data / SQLite

127.0.0.1:8082 ───────────────────────────► fixed Flask :5000
                                                └── fixed_data / SQLite

127.0.0.1:9000 ─► SonarQube Community Build ─► internal PostgreSQL
```

Ports 8080 and 8081 target exactly the same backend and SQLite database; the fixed implementation has its own volume, initialized from equivalent fixtures. Application sessions are signed cookies, and passwords are hashed. Alice and Bob have separate real sessions in the tests. The shared ticket #1003 authorizes both users, independently of the IDOR flaw.

The default Compose stack contains only the applications and WAF. Analysis tools and HTTP checks use separate profiles. The application containers run as UID 10001, with a read-only root filesystem, only a dedicated data volume, no Docker socket, no host source mount, restricted resources, cap_drop ALL and no-new-privileges. The lab bridge network explicitly has internal=false, allowing external routing. Ports 8080/8081/8082 are published only on 127.0.0.1. Runtime inspect and /proc confirmed these application restrictions; this is not an exhaustive container-isolation assessment.

## WAF configuration and experiment design

The selected official image is `owasp/modsecurity-crs:4.30.0-nginx-202610180210`, locked by digest. The official image README describes ModSecurity 3.0.17 and CRS 4.30.0 for this generation; the actual installed engine version remains to be recorded from the running container. See [versions](VERSIONS.md) and the [official image configuration](https://github.com/coreruleset/modsecurity-crs-docker).

`MODSEC_RULE_ENGINE=On` enables enforcement. Request body access is On. Blocking and detection paranoia levels are 1, and the inbound anomaly threshold is 5. No custom rule blocks a demonstration string or a particular ticket ID. The application does not synthesize WAF responses.

Response-body inspection is deliberately Off: the stored-XSS experiment measures prevention of the insertion request. It must not confuse response filtering with removal of stored data. Existing payloads are removed by the local CLI before each scenario; there is no unauthenticated HTTP reset endpoint.

Native/Serial audit logging goes to stdout. Sections ABFHZ retain the request URI, response status and messages containing rule IDs. The test harness adds a unique `lab_case` query parameter to each attack. The audit verifier requires a matching transaction, a 403 response and a detection-rule message; it does not accept an unrelated 403 or an anomaly-evaluation message alone.

## Scenarios, observations and fixes

| Scenario | Request and cause | Observed direct result | Observed fixed result | WAF status |
|---|---|---|---|---|
| SQLi | `/employees?q=`; f-string changes SQL syntax; input `' OR 1=1 -- ` | Normal `Алиса` returns 1 employee; injection returns 4 | Parameterized LIKE returns 0 for the injection | 403; 942100 + 949110 |
| Reflected XSS | `/greeting?name=` renders input with Jinja `safe`; `<script>alert("LAB_XSS")</script>` | Script tag present unescaped in HTML | Tag rendered as text via autoescaping; CSP also present | 403; 941100/941110/941160/941390 + 949110 |
| Stored XSS | POST `/tickets/1003`; script stored and rendered with `safe` | Bob's independent session receives Alice's unescaped script | Bob receives escaped literal script text | POST 403; 941100/941110/941160/941390 + 949110 |
| Command injection | POST `/diagnostics`; host appended to a shell command | Actual extra `LAB_TEST` command output on Linux with `;` | Input rejected with 400 before process execution | 403; 932235 + 949110 |
| Path traversal | `/download?file=..%2Flab-only.txt`; untrusted relative path joined to documents | `LAB_TRAVERSAL_PROOF` returned from outside documents | 400, marker absent; resolved path must remain inside documents | 403; 930110 + 949110 |
| IDOR | Alice changes `/tickets/1001` to `/tickets/1002` | Alice reads `BOB_PRIVATE`; Bob's owner session independently succeeds | Alice gets 403; Bob and shared-ticket participants retain access | 200; IDOR passed through WAF |

The shell payload for the primary Linux-container demonstration is `127.0.0.1; echo LAB_TEST`. The Windows fallback uses `127.0.0.1 & echo LAB_TEST`. The Windows fallback was tested earlier; the new run independently confirms Linux execution and ordinary ping permissions. Runtime is limited to approximately three seconds and captured output to 8192 bytes plus a short status message. A subprocess unit check also verified timeout and output limits.

Path traversal is carried in the query parameter, so URL path normalization cannot remove `../` before it reaches Flask. The requests library performs query encoding. The prepared file contains no real secret. The fixed implementation resolves the path and validates containment with `relative_to`, and its document tree is read-only in the container. Tests also covered absolute and alternate traversal paths.

Earlier local tests checked both reading and writing comments on another user's private ticket. The new container HTTP IDOR scenario checks GET with separate Alice/Bob sessions. The fixed implementation requires ownership or a participants-table entry before either GET or POST. Shared-ticket comments remain functional.

## Container runtime fixes

The packaged /usr/bin/ping carried cap_net_raw=ep while the application capability bounding set was empty. exec failed with EPERM before sending a packet. The shared Dockerfile now removes that file capability with `RUN /usr/sbin/setcap -r /usr/bin/ping`, before USER 10001:10001. Both rebuilt images have no security.capability xattr; all process capability sets remain zero, NoNewPrivs=1 and Seccomp=2. The unchanged ping_group_range is 0 2147483647, enabling unprivileged ICMP ping sockets. No NET_RAW, root, privileged mode or loader workaround was added.

The first post-fix run passed 53/54 HTTP checks: ping worked, but IDOR through WAF unexpectedly returned 403. Preserved evidence in `generated/ping-fix-first-run/` shows nexus_fixed cookies and the fixed application's CSP, without a CRS block message for that IDOR request. The old nginx process retained the backend address across app recreation and reached fixed. start/test now use `compose up --build --force-recreate`, preserving volumes and starting WAF after the healthy vulnerable backend. The final run passed 54/54; port 8081 was separately confirmed to issue nexus_vulnerable cookies. Application code, WAF rules and test expectations were not changed.

## Reproduction and WAF evidence

On Windows with Docker Desktop ready:

```powershell
.\scripts\lab.ps1 start
.\scripts\lab.ps1 test
.\scripts\lab.ps1 logs
```

The tests exercise login, normal pages, employee search, attachment content, ticket creation, persistent comments and loopback ping through all three entry points. They then check each attack's content or persisted effect. A failing check returns a non-zero exit code. The PowerShell wrapper cleans old shared-ticket comments before each mode, gathers genuine audit output and runs correlation checks.

The actual `http-waf.json`, `waf-evidence.json` and audit log are present. Five primary and five alternative attack requests each have a matching 403 transaction and detection IDs; 949110 evaluates the combined score. Login throttling is a separate nginx `limit_req` control, not a ModSecurity/CRS rule; its six rejected requests are evidenced in `generated/nginx-login-evidence.json` and `logs/login-rate.log`. See `BRUTE-FORCE.md` for behavior and fixed-version results. If another payload is not blocked, report that outcome and investigate it; do not silently change expectations or add a fake Flask filter.

## Browser and SonarQube evidence

Headless Chrome 155.0.8059.85 executed two reflected and two stored variants in the vulnerable portal. Alice submitted stored comments; Bob's separate browser context executed them. The WAF returned 403 for new attack requests; an already stored direct-backend payload still executed through the WAF route, showing that a proxy cannot clean stored database content. The fixed version displayed escaped content and produced no JavaScript dialogs. Evidence: `generated/browser-checks.json` and `screenshots/`.

SonarQube Community Build 26.10.0.133078 indexed 25 vulnerable and 27 fixed files. It reported 3/1 Issues, 0 Hotspots and `OK` quality gates. The two vulnerable-template findings are the expected autoescape bypasses. `python:S4502` appears in both versions at Flask initialization; the custom per-session CSRF check and its tests need to be reviewed in context. Full triage and JSON: `TASK-2-SAST.md` and `generated/sonar-*.json`.

## Limitations and conclusion

The local tests demonstrate the vulnerable code paths and their remediations without a WAF. The portal is an educational fixture, not a production security certification. These measurements confirm only tested cases, not all attack variants. IDOR illustrates why perimeter inspection cannot replace application-level authorization. Stored XSS illustrates why blocking new requests cannot repair an already contaminated database.
