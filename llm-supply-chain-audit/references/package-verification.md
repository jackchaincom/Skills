# Package Verification Guide

## Contents
- Slopsquatting Attack Overview
- Package Verification Methods
- Typosquatting Detection
- Lockfile Security
- Dependency Confusion Prevention
- Registry-Specific Checks

---

## Slopsquatting Attack Overview

### What Is Slopsquatting?

AI code assistants (Copilot, Cursor, Claude, ChatGPT) sometimes hallucinate non-existent package names. Attackers monitor these hallucinations and register the fake names on PyPI/npm with malicious payloads.

### Attack Chain

```
Step 1: AI generates code
  → "pip install flask-restful-swagger-3"  (doesn't exist)

Step 2: Attacker registers the name
  → pypi.org/project/flask-restful-swagger-3  (malicious!)

Step 3: Developer installs
  → pip install flask-restful-swagger-3  (malware)

Step 4: Malicious payload executes
  → Data exfiltration, crypto mining, reverse shell
```

### Real-World Examples (2024-2025)

| Package | Registry | Attack Type | Impact |
|---------|----------|-------------|--------|
| `@chatgptclaude_club/claude-code` | npm | Impersonation | Credential theft |
| `langchain-community-tools` | PyPI | Hallucination | Malware |
| `openai-functions` | PyPI | Hallucination | Data exfil |
| `python-binance` | PyPI | Typosquat | Crypto theft |
| `colorama` (fake) | PyPI | Typosquat | Malware |

---

## Package Verification Methods

### Method 1: Registry Existence Check

```python
import requests
from urllib.parse import quote

def verify_pypi_package(name: str) -> dict:
    """Check if a PyPI package exists and is legitimate."""
    result = {"name": name, "exists": False, "risks": []}

    resp = requests.get(f"https://pypi.org/pypi/{quote(name)}/json", timeout=10)

    if resp.status_code == 404:
        result["risks"].append({
            "level": "CRITICAL",
            "message": f"Package '{name}' does NOT exist on PyPI",
        })
        return result

    if resp.status_code != 200:
        result["risks"].append({
            "level": "WARNING",
            "message": f"Could not verify (HTTP {resp.status_code})",
        })
        return result

    result["exists"] = True
    data = resp.json()
    info = data.get("info", {})

    # Gather metadata
    result["version"] = info.get("version")
    result["summary"] = info.get("summary", "")
    result["author"] = info.get("author", "")
    result["home_page"] = info.get("home_page", "")
    result["project_urls"] = info.get("project_urls", {})

    return result


def verify_npm_package(name: str) -> dict:
    """Check if an npm package exists and is legitimate."""
    result = {"name": name, "exists": False, "risks": []}

    encoded = quote(name, safe="@/")
    resp = requests.get(f"https://registry.npmjs.org/{encoded}", timeout=10)

    if resp.status_code == 404:
        result["risks"].append({
            "level": "CRITICAL",
            "message": f"Package '{name}' does NOT exist on npm",
        })
        return result

    result["exists"] = True
    data = resp.json()
    result["version"] = data.get("dist-tags", {}).get("latest")
    result["description"] = data.get("description", "")

    return result
```

### Method 2: Age and Popularity Check

```python
from datetime import datetime, timedelta

def check_package_age(pypi_data: dict) -> list:
    """Check package age for suspiciousness."""
    risks = []
    releases = pypi_data.get("releases", {})

    if not releases:
        risks.append({"level": "HIGH", "message": "No release history"})
        return risks

    # Find earliest release
    earliest = None
    for version_files in releases.values():
        for file_info in version_files:
            upload_time = file_info.get("upload_time")
            if upload_time:
                dt = datetime.fromisoformat(upload_time.rstrip("Z"))
                if earliest is None or dt < earliest:
                    earliest = dt

    if earliest:
        age = datetime.now() - earliest
        if age < timedelta(days=7):
            risks.append({
                "level": "HIGH",
                "message": f"Very new package ({age.days} days old)",
            })
        elif age < timedelta(days=30):
            risks.append({
                "level": "MEDIUM",
                "message": f"New package ({age.days} days old)",
            })

    return risks


def check_download_count(package_name: str) -> list:
    """Check PyPI download count via pypistats API."""
    risks = []

    try:
        resp = requests.get(
            f"https://pypistats.org/api/packages/{package_name}/recent",
            timeout=10,
        )
        if resp.ok:
            data = resp.json()
            last_month = data.get("data", {}).get("last_month", 0)
            if last_month < 100:
                risks.append({
                    "level": "MEDIUM",
                    "message": f"Very low downloads ({last_month}/month)",
                })
            elif last_month < 1000:
                risks.append({
                    "level": "LOW",
                    "message": f"Low downloads ({last_month}/month)",
                })
    except Exception:
        pass

    return risks
```

### Method 3: Maintainer Verification

```python
def check_maintainer_signals(pypi_info: dict) -> list:
    """Check for trust signals in package metadata."""
    risks = []

    # No project URLs
    project_urls = pypi_info.get("project_urls") or {}
    if not project_urls:
        risks.append({
            "level": "MEDIUM",
            "message": "No project URLs / repository link",
        })

    # No homepage
    if not pypi_info.get("home_page") and "Homepage" not in project_urls:
        risks.append({
            "level": "LOW",
            "message": "No homepage URL",
        })

    # Minimal description
    summary = pypi_info.get("summary", "")
    if len(summary) < 20:
        risks.append({
            "level": "MEDIUM",
            "message": f"Minimal description ({len(summary)} chars)",
        })

    # No license
    if not pypi_info.get("license"):
        risks.append({
            "level": "LOW",
            "message": "No license specified",
        })

    return risks
```

---

## Typosquatting Detection

### Levenshtein Distance Algorithm

```python
def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            current_row.append(min(
                previous_row[j + 1] + 1,   # insertion
                current_row[j] + 1,         # deletion
                previous_row[j] + (c1 != c2)  # substitution
            ))
        previous_row = current_row
    return previous_row[-1]
```

### Popular Package Database

```python
POPULAR_AI_PACKAGES = {
    "pypi": {
        # Core AI/ML
        "langchain": 5000000,
        "langchain-core": 4000000,
        "langchain-community": 3000000,
        "langchain-openai": 2000000,
        "openai": 10000000,
        "anthropic": 3000000,
        "transformers": 8000000,
        "torch": 15000000,
        "tensorflow": 12000000,

        # Vector stores
        "chromadb": 2000000,
        "pinecone-client": 1500000,
        "qdrant-client": 800000,
        "weaviate-client": 600000,
        "faiss-cpu": 3000000,

        # LLM tools
        "tiktoken": 5000000,
        "sentence-transformers": 4000000,
        "llama-index": 1000000,
        "huggingface-hub": 6000000,

        # Common utilities
        "pydantic": 20000000,
        "fastapi": 15000000,
        "requests": 50000000,
        "numpy": 60000000,
        "pandas": 40000000,
    },
}

def check_typosquatting(package_name: str, registry: str = "pypi") -> list:
    """Check if package name is suspiciously similar to popular packages."""
    risks = []
    popular = POPULAR_AI_PACKAGES.get(registry, {})

    normalized = package_name.lower().replace("-", "").replace("_", "")

    for popular_name in popular:
        if popular_name == package_name:
            continue

        normalized_popular = popular_name.lower().replace("-", "").replace("_", "")
        distance = levenshtein_distance(normalized, normalized_popular)

        if distance == 1:
            risks.append({
                "level": "HIGH",
                "message": f"Very similar to '{popular_name}' (1 char difference) - possible typosquatting",
            })
        elif distance == 2 and len(package_name) > 5:
            risks.append({
                "level": "MEDIUM",
                "message": f"Similar to '{popular_name}' (2 char difference)",
            })

    # Check for common deception patterns
    deception_patterns = [
        (r"-py$", "Suspicious '-py' suffix"),
        (r"-python$", "Suspicious '-python' suffix"),
        (r"^python-", "Suspicious 'python-' prefix"),
        (r"-v\d+$", "Suspicious version suffix"),
        (r"-extra$", "Suspicious '-extra' suffix"),
        (r"-utils$", "Could be legitimate, verify"),
        (r"-tools$", "Could be legitimate, verify"),
    ]

    import re
    for pattern, message in deception_patterns:
        base = re.sub(pattern, "", package_name)
        if base in popular and base != package_name:
            risks.append({
                "level": "MEDIUM",
                "message": f"{message}: '{package_name}' looks like '{base}' with added suffix",
            })

    return risks
```

---

## Lockfile Security

### Lockfile Verification Checklist

```
- [ ] requirements.txt committed to version control
- [ ] pip freeze output matches requirements
- [ ] package-lock.json committed to version control
- [ ] No wildcard versions (>=, ~=, *)
- [ ] Hash verification enabled where possible
```

### Pinned Requirements

```python
# ❌ UNSAFE - allows any version
langchain
openai>=1.0

# ⚠️ RISKY - allows minor/patch updates
langchain~=0.3.0
openai>=1.0,<2.0

# ✅ SAFE - exact version pinned
langchain==0.3.7
openai==1.51.2
```

### Hash Verification (pip)

```bash
# Generate requirements with hashes
pip freeze --all | pip hash --algorithm sha256

# requirements.txt with hashes
langchain==0.3.7 \
    --hash=sha256:abc123def456...

# Install with hash verification
pip install --require-hashes -r requirements.txt
```

---

## Dependency Confusion Prevention

### Attack Overview

```
Internal Registry: company-ml-utils v1.0.0  (private)
Public PyPI:       company-ml-utils v9.9.9  (malicious, higher version)

pip install company-ml-utils
→ Installs v9.9.9 from PyPI (malicious!) instead of internal v1.0.0
```

### Prevention

```ini
# pip.conf - restrict to internal registry
[global]
index-url = https://internal.pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# Or use package namespace
# Internal packages: @company/ml-utils (npm) or company-ml-utils (PyPI)
```

```python
# pyproject.toml - specify sources
[tool.poetry.source]
name = "internal"
url = "https://internal.pypi.company.com/simple/"
priority = "primary"

[[tool.poetry.source]]
name = "pypi"
priority = "supplemental"
```

---

## Registry-Specific Checks

### PyPI Security Features

```bash
# pip-audit: Check for known vulnerabilities
pip install pip-audit
pip-audit -r requirements.txt

# safety: Alternative vulnerability scanner
pip install safety
safety check -r requirements.txt

# pip with hash verification
pip install --require-hashes -r requirements.txt
```

### npm Security Features

```bash
# Built-in audit
npm audit
npm audit fix

# Check for known vulnerabilities
npx auditjs@latest ossi

# Lock-only install (no modification)
npm ci
```

### Automated Verification Workflow

```python
def full_package_audit(requirements_file: str) -> dict:
    """Run complete package audit."""
    results = {
        "total": 0,
        "safe": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "packages": [],
    }

    packages = parse_requirements(requirements_file)
    results["total"] = len(packages)

    for pkg_name in packages:
        pkg_result = verify_pypi_package(pkg_name)

        if not pkg_result["exists"]:
            results["critical"] += 1
        else:
            # Run all checks
            resp = requests.get(f"https://pypi.org/pypi/{pkg_name}/json")
            data = resp.json()

            risks = []
            risks.extend(check_package_age(data))
            risks.extend(check_download_count(pkg_name))
            risks.extend(check_maintainer_signals(data.get("info", {})))
            risks.extend(check_typosquatting(pkg_name))

            pkg_result["risks"].extend(risks)

            max_level = max(
                (r["level"] for r in pkg_result["risks"]),
                default="SAFE",
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4}[x],
            )

            if max_level == "SAFE":
                results["safe"] += 1
            else:
                results[max_level.lower()] = results.get(max_level.lower(), 0) + 1

        results["packages"].append(pkg_result)

    return results
```
