"""Read official registry metadata; does not pull or claim to run images."""
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
images = [
    ("library/python", "3.12.15-slim-bookworm"),
    ("owasp/modsecurity-crs", "4.30.0-nginx-202610180210"),
    ("library/sonarqube", "26.10.0.133078-community"),
    ("sonarsource/sonar-scanner-cli", "12.2.0.4256_8.1.0"),
    ("semgrep/semgrep", "1.181.0"),
    ("library/postgres", "17.9-bookworm"),
]
records = []
for repository, tag in images:
    url = f"https://hub.docker.com/v2/repositories/{repository}/tags/{tag}"
    with urlopen(url, timeout=40) as response:
        metadata = json.load(response)
    records.append({"repository": repository, "tag": tag, "digest": metadata["digest"],
                    "last_updated": metadata["last_updated"], "source": url,
                    "architectures": sorted({item["architecture"] for item in metadata.get("images", [])})})
    print(f"PASS registry tag exists: {repository}:{tag}", flush=True)
snapshot = ROOT / "sast" / "registry-python.yml"
report = {"checked_on": "2026-10-21", "verification": "Registry metadata only, images not pulled or executed",
          "images": records, "semgrep_registry": {"url": "https://semgrep.dev/c/p/python", "rules": 151,
          "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest()}}
(ROOT / "reports" / "generated" / "versions.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
