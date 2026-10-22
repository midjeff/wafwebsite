# Assignment 2 — Static analysis, triage and remediation

## Scope, tools and actual execution

Two complete source trees were analyzed independently: `app/` (vulnerable) and `app-fixed/` (remediated). Test payloads, reports and the other implementation are excluded from each project's scan scope. The applications are separate code implementations, not a runtime switch that rejects known demonstration strings.

**Semgrep Community Edition 1.181.0 actually ran on Windows.** The scan used `--oss-only`, disabled metrics/version checks and `--strict`. The official `p/python` Registry response was preserved locally, with 151 rules and their metadata/licenses. Four clearly identified educational rules were run separately. JSON, SARIF and tool logs are retained for all four scans. No Semgrep Pro engine or service login was used.

**SonarQube Community Build was not executed.** Docker is now installed and the application/WAF stack is running, but SonarQube setup, scanning and export have not been performed. Two project configurations, persistent services, a scanner and a paginated API export script are prepared. Its counts and rule IDs are **NOT RUN**, never zero-by-assumption. After initial setup, run `scripts/lab.ps1 scan-sonar` and append actual observations. See [setup](SONAR-SETUP.md).

| Actual Semgrep run | Files scanned | Findings | Technical result |
|---|---:|---:|---|
| Vulnerable / Registry | 4 Python files | 0 | PASS |
| Fixed / Registry | 4 Python files | 0 | PASS |
| Vulnerable / custom | 22 files | 5 | PASS |
| Fixed / custom | 22 files | 1 | PASS |

The generic template rule accounts for the larger custom scan scope. All four JSON reports have no scanner errors. A successful scan can contain findings: the wrapper does not use `--error`, but does fail for a non-zero technical exit, parse errors or zero scanned files. Exact results and rule-set hashes are in `generated/semgrep-summary.json`. These are the earlier Windows Semgrep results, retained unchanged; Semgrep was not rerun during the 22 October ping/container fix.

## Classification and free-edition limits

A confirmed vulnerability is supported by a reachable unsafe data flow and a demonstrated security failure. A Security Hotspot flags a security-sensitive operation for review; it is not proof of exploitability. A code-quality issue may concern complexity, duplication or maintainability without a security failure. These categories must remain separate during SonarQube triage.

Community Build is used without paid branch-analysis or advanced taint-analysis assumptions. The two separate projects avoid needing commercial branch comparison. The [official feature comparison](https://docs.sonarsource.com/sonarqube-community-build/feature-comparison-table) and [SonarQube repository](https://github.com/SonarSource/sonarqube) distinguish Community Build from commercial capabilities. Actual detection depends on the installed analyzer and active profile, so no universal SQLi/XSS discovery is promised.

Semgrep CE findings also depend on the selected rules and analysis scope. The Registry scan's zero findings did **not** establish safety: dynamic checks demonstrate several vulnerabilities in the same source. We did not modify the source or invent rules based on known filenames to make every class appear detected. IDOR remains a contextual authorization problem, confirmed by two-session checks rather than an artificial rule.

## Confirmed findings and their remediation

The following rule IDs and locations are taken from the actual custom Semgrep JSON. The prefix `sast.` is emitted by Semgrep for the local configuration path. Template source is compact, so both template findings are on line 1; JSON/SARIF retain the exact column and range.

### F1 — SQL injection (CWE-89)

- Tool/rule: Semgrep CE, **custom** `sast.lab-sql-string-construction`.
- Location: `app/main.py:159` (sink); SQL construction at line 157.
- Unsafe code: `sql = f"SELECT ... WHERE name LIKE '%{query}%' ORDER BY id"`, then `get_db().execute(sql)`.
- Cause: request data becomes SQL syntax rather than a bound value. An authenticated user can broaden the employee query and retrieve additional synthetic rows.
- Confirmation: normal search `Алиса` returned one employee; `' OR 1=1 -- ` returned four, using both Flask test client and real HTTP.
- Fix: `app-fixed/main.py:161–163` uses `WHERE name LIKE ?` and a parameter tuple. The LIKE wildcards are inside the value, not SQL source.
- Retest: the attack returned zero employees with HTTP 200; alternate injection syntax also failed to alter the result. The custom SQL finding disappeared. Registry rules reported zero before and after; SonarQube not run.

### F2 — Reflected XSS (CWE-79)

- Tool/rule: Semgrep CE, **custom** `sast.lab-jinja-autoescape-bypass`.
- Location: `app/templates/greeting.html:1`, column 254.
- Unsafe code: `{{ name|safe }}`; `name` originates in the request query.
- Cause/consequence: an authenticated request can insert executable HTML into the response. The harmless demonstration is `<script>alert("LAB_XSS")</script>`.
- Confirmation: the raw script tag was present in vulnerable HTML. Browser execution has **not** been observed in this session and remains a manual step.
- Fix: `{{ name }}` with Jinja HTML autoescaping. The fixed application also sends a restrictive CSP, but escaping is the primary fix.
- Retest: fixed HTML contains `&lt;script&gt;` and not the raw payload. The custom finding disappeared. Browser no-dialog confirmation pending; Registry zero/zero; SonarQube not run.

### F3 — Stored XSS (CWE-79)

- Tool/rule: Semgrep CE, **custom** `sast.lab-jinja-autoescape-bypass`.
- Location: `app/templates/ticket.html:1`, column 823.
- Unsafe code: `{{ comment.body|safe }}`.
- Cause/consequence: comments are parameterized when stored in SQLite, but rendered as trusted HTML later. SQL parameterization does not prevent HTML injection. Another authorized participant receives the stored script.
- Confirmation: Alice submitted `<script>alert("LAB_STORED")</script>` to shared ticket #1003; Bob's separate session received the unescaped script. Both users legitimately participate, so this test does not depend on IDOR. CLI cleanup was also verified.
- Fix: `{{ comment.body }}` in the fixed template. Comments remain stored and usable, with escaping at the HTML output context.
- Retest: Bob received escaped literal script text; ordinary comments remained functional. The custom finding disappeared. Browser dialog checks pending; Registry zero/zero; SonarQube not run.

### F4 — OS command injection (CWE-78)

- Tool/rule: Semgrep CE, **custom** `sast.lab-shell-enabled`.
- Location: `app/main.py:191`; command assembly immediately above.
- Unsafe code: `command = " ".join(ping_arguments()) + " " + host`; `bounded_run(command, shell=True)` reaches `subprocess.Popen`.
- Cause/consequence: shell metacharacters supplied as host input start an additional command. Process/output limits reduce resource impact but do not remove injection.
- Confirmation: a real Windows subprocess returned `LAB_TEST` for `127.0.0.1 & echo LAB_TEST`. The new Linux-container run also returned `LAB_TEST` for `127.0.0.1; echo LAB_TEST`; fixed returned 400 and WAF blocked the request with rule 932235.
- Fix: parse with `ipaddress.ip_address`, restrict the diagnostic to loopback, pass a list of arguments and set `shell=False`.
- Retest: malicious input returned 400 before execution; normal loopback ping succeeded; alternate commands, command options, external IPs and hostnames were rejected. The custom finding disappeared. Registry zero/zero; SonarQube not run.

### F5 — Path traversal (CWE-22)

- Tool/rule: Semgrep CE, **custom** `sast.lab-request-to-send-file`.
- Location: `app/main.py:181`; path construction at line 178.
- Unsafe code: `ROOT / "documents" / request.args.get("file", "onboarding.txt")` followed by `send_file(target, ...)`.
- Cause/consequence: joining a directory with an untrusted path does not enforce containment. A requester can read a prepared file outside the intended documents directory.
- Confirmation: `file=../lab-only.txt` returned `LAB_TRAVERSAL_PROOF`. Only synthetic data was read.
- Fix: resolve the permitted root and requested path; require `target.relative_to(directory)` to succeed, aborting on errors. The immutable document tree in the container prevents an attacker from swapping a symlink between validation and open through normal portal functions.
- Retest: traversal returned 400 and the marker was absent; ordinary download, absolute-path escape and alternate traversal checks passed. The custom warning **remains** in the fixed code and is triaged below. Registry zero/zero; SonarQube not run.

### F6 — IDOR / missing object authorization (CWE-639, CWE-862)

- Tool/rule: **manual source review and authenticated behavior tests; no SAST finding**.
- Location: `app/main.py:131–136`, `load_ticket` checks existence but not ownership; login is enforced separately.
- Unsafe code path: select a ticket by request-controlled integer ID, then return it to any authenticated user.
- Cause/consequence: authentication answers who the caller is, but not whether that caller may access this ticket. Alice can read Bob's `BOB_PRIVATE` ticket and write to it.
- Confirmation: Alice and Bob use separate session clients; Bob can open #1002; Alice can also open it in the vulnerable application. A forged `user_id` query does not authenticate an anonymous client.
- Fix: `app-fixed/main.py:136–139` checks owner ID or a participants-table row before either GET or POST.
- Retest: Alice receives 403 and cannot write to #1002; Bob retains access. Both can read/write shared #1003. Neither Semgrep group detected IDOR; SonarQube not run. This is an explicit missed class, not a fabricated scanner success.

## Residual warning in the fixed implementation

`sast.lab-request-to-send-file` still reports `app-fixed/main.py:189`. Manual review and dynamic tests classify this warning as a **false positive for the demonstrated traversal under the lab's immutable document-tree assumption**. The request reaches a file-serving sink, but lines 181–186 canonicalize the path and require containment; the error path aborts. The educational taint rule does not prove that control-flow property across the try/abort path.

The warning has not been hidden with `nosemgrep`, path exclusions or a filename-specific rule. Its presence is useful for showing why a warning requires triage. This decision does not prove that every possible filesystem deployment is safe: a separately writable document tree or symlink-changing attacker would require renewed analysis.

## Comparative coverage

| Scenario | SonarQube | Semgrep Registry | Semgrep custom | Manual review + behavior | Remaining limitation |
|---|---|---|---|---|---|
| SQLi | NOT RUN | Missed in this run | Confirmed finding, gone after fix | 1 → 4 rows; fixed 0 | Tested payload only; no general bypass guarantee |
| Reflected XSS | NOT RUN | Missed in this run | Confirmed unsafe sink, gone after fix | Raw vs escaped HTML | Browser JS pending |
| Stored XSS | NOT RUN | Missed in this run | Confirmed unsafe sink, gone after fix | Two legitimate sessions, stored raw vs escaped HTML | Browser JS pending |
| Command injection | NOT RUN | Missed in this run | Confirmed finding, gone after fix | Actual Windows and Linux echo; fixed 400, WAF 403 | Tested payload only |
| Path traversal | NOT RUN | Missed in this run | Confirmed before; residual false positive after | Outside marker vs 400 | Immutable-tree assumption |
| IDOR | NOT RUN | Missed | Missed | Cross-user GET/POST vs 403 | Business policy requires human review |

## Reproduce and complete

```powershell
.\scripts\lab.ps1 scan-semgrep
.\scripts\lab.ps1 sonar
# First-time UI setup and token entry: SONAR-SETUP.md
.\scripts\lab.ps1 scan-sonar
```

Attach genuine Sonar issues and hotspots separately, record rule/profile versions, distinguish security findings from code-quality issues and compare source lines with the actual scanned revision. Do not infer a clean Sonar result from a missing export. Semgrep snapshots and all current raw results are already included. Behavioral evidence remains necessary even when a scanner reports no warning.
