---
name: llm-supply-chain-audit
description: Audits AI/ML supply chain security including model files, package dependencies, and external services. Detects slopsquatting attacks (AI-hallucinated packages), poisoned models, unsafe deserialization, MCP server risks, and CI/CD pipeline vulnerabilities. Use before deploying AI applications or when integrating third-party models and packages.
---

# LLM Supply Chain Security Audit

Comprehensive supply chain security auditor for AI/ML applications, focusing on model integrity, dependency verification, and external service risks.

## When to Use

- Before deploying AI/ML models to production
- When integrating third-party models from Hugging Face or other registries
- Auditing Python/npm dependencies in AI projects
- Reviewing MCP (Model Context Protocol) server configurations
- Setting up CI/CD pipelines for AI applications
- After AI assistants suggest new packages to install

## Audit Types

### Quick Audit
Fast check for critical supply chain risks:
```
Audit Progress:
- [ ] Verify all packages exist on registries
- [ ] Check for known malicious packages
- [ ] Scan for unsafe model loading patterns
- [ ] Detect hardcoded model URLs
```

### Full Audit
Comprehensive supply chain assessment:
```
Audit Progress:
- [ ] Package existence verification (PyPI/npm)
- [ ] Package age and popularity analysis
- [ ] Typosquatting detection
- [ ] Model file format security check
- [ ] Model source verification
- [ ] MCP server configuration audit
- [ ] CI/CD pipeline security review
- [ ] Dependency lockfile analysis
- [ ] Container image scanning recommendations
```

## Audit Workflow

### Step 1: Dependency Inventory

Collect all dependencies from project files:

```bash
# Python dependencies
find . -name "requirements*.txt" -o -name "pyproject.toml" -o -name "setup.py" | head -20

# Node.js dependencies
find . -name "package.json" -not -path "*/node_modules/*" | head -10

# Model files
find . -name "*.pt" -o -name "*.pth" -o -name "*.pkl" -o -name "*.h5" -o -name "*.safetensors" | head -20
```

### Step 2: Run Automated Audits

Execute audit scripts:

```bash
# Full supply chain audit
python scripts/supply-chain-auditor.py /path/to/project

# Model-specific security scan
python scripts/model-scanner.py /path/to/models/
```

### Step 3: Manual Review

For each risk category, consult:
- [references/model-security.md](references/model-security.md) - Model file security
- [references/package-verification.md](references/package-verification.md) - Package authenticity
- [references/mcp-security.md](references/mcp-security.md) - MCP protocol risks

### Step 4: Generate Report

Use template: [assets/audit-report-template.md](assets/audit-report-template.md)

## Critical Detection Patterns

### Slopsquatting (AI Hallucination Attacks)

```python
# CRITICAL: AI-suggested packages that may not exist
pip install langchain-community-tools  # Does this exist?
pip install openai-functions           # Hallucinated name!
pip install anthropic-tools            # Check registry first!

# Always verify before installing
import requests
resp = requests.get(f"https://pypi.org/pypi/{package_name}/json")
if resp.status_code == 404:
    raise ValueError(f"Package '{package_name}' does not exist!")
```

### Unsafe Model Loading

```python
# CRITICAL: Pickle-based deserialization allows RCE
model = torch.load("model.pt")           # Arbitrary code execution!
data = pickle.load(open("data.pkl"))     # Never trust pickle files!
model = joblib.load("model.joblib")      # Uses pickle internally!

# SAFE: Use safetensors format
from safetensors.torch import load_model
model = load_model(model, "model.safetensors")  # No code execution

# SAFER: Use weights_only (Python 3.12+)
model = torch.load("model.pt", weights_only=True)
```

### Model Source Verification

```python
# CRITICAL: Unverified model sources
model = AutoModel.from_pretrained(user_input)      # RCE via pickle!
model = AutoModel.from_pretrained("random/model")  # Unknown source!

# SAFE: Use allowlist and pin revisions
ALLOWED_MODELS = {"openai/whisper-large-v3", "meta-llama/Llama-3.1-70B"}
model = AutoModel.from_pretrained(
    "meta-llama/Llama-3.1-70B",
    revision="abc123def456",        # Pin to specific commit
    trust_remote_code=False,        # NEVER True for untrusted models
)
```

### MCP Server Configuration Risks

```python
# CRITICAL: CVE-2025-54136 (MCPoison) - Untrusted MCP servers
mcp_servers:
  - url: "https://malicious-server.com/mcp"  # Untrusted source!
  - command: "npx unknown-mcp-tool"           # Unknown package!

# SAFE: Use allowlisted servers only
ALLOWED_MCP_SERVERS = {"localhost:3000", "mcp.internal.company.com"}
```

## Risk Categories

### Package Risks

| Indicator | Risk Level | Description |
|-----------|------------|-------------|
| Package doesn't exist | CRITICAL | AI hallucination / slopsquatting |
| Package < 7 days old | HIGH | Potentially malicious new upload |
| Package < 30 days old | MEDIUM | Verify legitimacy |
| No repository URL | MEDIUM | Cannot verify source |
| Name similar to popular package | HIGH | Typosquatting |
| Single maintainer, no docs | MEDIUM | Low trust signal |

### Model File Risks

| Format | Risk Level | Reason |
|--------|------------|--------|
| `.pt`, `.pth` (PyTorch) | CRITICAL | Pickle-based, arbitrary code execution |
| `.pkl`, `.pickle` | CRITICAL | Python pickle, arbitrary code execution |
| `.joblib` | CRITICAL | Uses pickle internally |
| `.h5` (Keras) | HIGH | Can contain Lambda layers with code |
| `.onnx` | LOW | Declarative format, safer |
| `.safetensors` | SAFE | No code execution possible |

### MCP Protocol Risks

| Pattern | Risk Level | Description |
|---------|------------|-------------|
| Remote MCP server | HIGH | External code execution |
| Unknown npx package | CRITICAL | Supply chain attack vector |
| No server allowlist | HIGH | Unrestricted connections |
| stdio transport without validation | MEDIUM | Local process risks |

## Framework-Specific Checks

### Hugging Face Transformers

| Pattern | Risk | Recommendation |
|---------|------|----------------|
| `from_pretrained` without `revision` | HIGH | Pin to specific commit |
| `trust_remote_code=True` | CRITICAL | Set to False |
| `AutoModel.from_pretrained(user_input)` | CRITICAL | Use allowlist |
| No `safetensors` preference | MEDIUM | Set `use_safetensors=True` |

### LangChain

| Pattern | Risk | Recommendation |
|---------|------|----------------|
| Dynamic tool loading | HIGH | Use static tool list |
| `load_tools` from user input | CRITICAL | Allowlist tools |
| Unverified document loaders | HIGH | Validate URLs |

### PyTorch

| Pattern | Risk | Recommendation |
|---------|------|----------------|
| `torch.load()` | CRITICAL | Use `weights_only=True` |
| Loading from URL | HIGH | Verify hash/signature |
| Custom model classes | MEDIUM | Review code carefully |

## Severity Classification

| Severity | Description | Action |
|----------|-------------|--------|
| CRITICAL | Immediate RCE or supply chain compromise | Block deployment |
| HIGH | Significant risk, likely exploitable | Fix before production |
| MEDIUM | Potential issue, needs verification | Fix in next sprint |
| LOW | Best practice violation | Consider fixing |
| INFO | Informational finding | Document and monitor |

## Key Files to Audit

### Always Check
- `requirements.txt`, `requirements-*.txt` - Direct dependencies
- `pyproject.toml` - Modern Python projects
- `package.json`, `package-lock.json` - Node.js projects
- `*.pt`, `*.pth`, `*.pkl` - Model files
- `Dockerfile` - Container builds
- `.github/workflows/*.yml` - CI/CD pipelines

### High Priority
- `mcp.json`, `mcp-config.yaml` - MCP configurations
- `models/` directory - Model storage
- `data/` directory - Training data
- `.env`, `secrets.*` - Configuration files

## Output Format

```
[SEVERITY] Category: Description
  File: path/to/file
  Risk: Detailed risk explanation
  Evidence: Specific finding
  Fix: Recommended remediation
  Reference: Link to documentation
```

## CI/CD Integration

### GitHub Actions Security Gate

```yaml
name: Supply Chain Audit
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Audit Python dependencies
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt --strict

      - name: Check for unsafe model loading
        run: |
          if grep -rE "torch\.load|pickle\.load|joblib\.load" --include="*.py" .; then
            echo "::warning::Potentially unsafe model loading detected"
          fi

      - name: Verify packages exist
        run: |
          python .claude/skills/llm-supply-chain-audit/scripts/supply-chain-auditor.py .
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: supply-chain-audit
        name: Supply Chain Audit
        entry: python .claude/skills/llm-supply-chain-audit/scripts/supply-chain-auditor.py
        language: python
        types: [python]
        pass_filenames: false
```

## Quick Commands

```bash
# Verify a single package exists
python -c "import requests; print('EXISTS' if requests.get('https://pypi.org/pypi/PACKAGE/json').ok else 'NOT FOUND')"

# List all pickle-based files
find . -name "*.pt" -o -name "*.pth" -o -name "*.pkl" -o -name "*.joblib"

# Check for unsafe loading patterns
grep -rE "torch\.load|pickle\.load|joblib\.load" --include="*.py" .

# Audit with pip-audit
pip-audit -r requirements.txt --desc on
```

## References

- [references/model-security.md](references/model-security.md) - Model file security guide
- [references/package-verification.md](references/package-verification.md) - Package verification methods
- [references/mcp-security.md](references/mcp-security.md) - MCP protocol security
