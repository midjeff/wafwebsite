"""Correlate actual ModSecurity native audit records with each blocked test."""
import argparse
import json
from pathlib import Path
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--log", default="/logs/waf.log")
parser.add_argument("--report", default="/reports/http-waf.json")
parser.add_argument("--output", default="/reports/waf-evidence.json")
args = parser.parse_args()
log = Path(args.log).read_text(encoding="utf-8-sig", errors="replace")
http = json.loads(Path(args.report).read_text(encoding="utf-8"))
# Native transaction boundaries: --<unique-id>-A-- ... --<unique-id>-Z--.
transactions = []
# v2 uses --id-A--; v3 can use ---id---A--. Preserve the exact delimiter.
for start in re.finditer(r"(?m)^(--[^\r\n]+?-A--)\r?$", log):
    end_marker = start.group(1)[:-3] + "Z--"
    end = log.find(end_marker, start.end())
    if end != -1:
        transactions.append(log[start.start():end + len(end_marker)])
evidence = []
for case in [row for row in http["results"] if row.get("attack")]:
    matching = [item for item in transactions if "lab_case=" + case["case_id"] in item]
    messages = []
    for transaction in matching:
        for line in transaction.splitlines():
            rule = re.search(r'\[id "(\d+)"\]', line)
            message = re.search(r'\[msg "([^\"]+)"\]', line)
            if rule and message:
                messages.append({"rule_id": rule.group(1), "message": message.group(1)})
    # Require a detection rule as well as any anomaly evaluation rule.
    detected = any(not item["rule_id"].startswith(("949", "980")) for item in messages)
    blocked = any(re.search(r"HTTP/\S+ 403", record) for record in matching)
    passed = bool(case["passed"] and matching and detected and blocked)
    evidence.append({"name": case["name"], "case_id": case["case_id"], "passed": passed, "rules": messages})
    print(f"{'PASS' if passed else 'FAIL'} audit {case['name']}: {len(matching)} transaction(s), rules={messages}")
required = {'SQLi', 'Reflected XSS', 'Stored XSS', 'Command Injection', 'Path Traversal'}
required |= {name + ' alternate' for name in list(required)}
complete = len(evidence) == 10 and {item['name'] for item in evidence} == required and all(item["passed"] for item in evidence)
Path(args.output).write_text(json.dumps({"complete": complete, "evidence": evidence}, ensure_ascii=False, indent=2), encoding="utf-8")
sys.exit(0 if complete else 1)
