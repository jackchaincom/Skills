# AI/ML Supply Chain Security

## Contents
- Slopsquatting Attacks
- Model Poisoning
- Dependency Confusion
- MCP Protocol Risks
- Malicious Model Files
- CI/CD Pipeline Threats
- Detection and Prevention

---

## Slopsquatting Attacks

### Risk Level: CRITICAL

AI code assistants hallucinate non-existent package names. Attackers register these hallucinated names on PyPI/npm with malicious code.

### How It Works

```
1. AI assistant generates code:
   "pip install flask-restful-swagger-3"  ← hallucinated package name

2. Attacker monitors AI suggestions and registers the package:
   pypi.org/project/flask-restful-swagger-3  ← malicious!

3. Developer installs the hallucinated package:
   pip install flask-restful-swagger-3  ← installs malware
```

### Real-World Examples (2025)

- **@chatgptclaude_club/claude-code** - npm package impersonating Anthropic CLI
- Multiple PyPI packages named after common AI hallucinations
- NPM packages targeting Copilot-suggested names

### Detection Patterns

```python
SLOPSQUATTING_INDICATORS = [
    # Suspiciously new packages
    {
        "check": "creation_date",
        "threshold": "< 30 days old",
        "severity": "HIGH",
    },
    # Low download counts
    {
        "check": "weekly_downloads",
        "threshold": "< 100",
        "severity": "MEDIUM",
    },
    # Name similarity to popular packages
    {
        "check": "name_distance",
        "threshold": "levenshtein_distance < 3 from popular package",
        "severity": "HIGH",
    },
    # Missing or minimal documentation
    {
        "check": "description_length",
        "threshold": "< 50 characters",
        "severity": "MEDIUM",
    },
    # Single maintainer, no repository link
    {
        "check": "maintainer_count",
        "threshold": "== 1 AND no repo URL",
        "severity": "HIGH",
    },
]
```

### Verification Script Logic

```python
import requests
from datetime import datetime, timedelta

def check_package_legitimacy(package_name: str, registry: str = "pypi") -> dict:
    """Check if a package is potentially malicious."""
    findings = []

    if registry == "pypi":
        resp = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        if resp.status_code == 404:
            findings.append({
                "severity": "CRITICAL",
                "message": f"Package '{package_name}' does not exist on PyPI. "
                           f"Possible AI hallucination.",
            })
            return {"package": package_name, "findings": findings}

        data = resp.json()
        info = data.get("info", {})

        # Check age
        releases = data.get("releases", {})
        if releases:
            first_release = min(
                (v[0]["upload_time"] for v in releases.values() if v),
                default=None
            )
            if first_release:
                age = datetime.now() - datetime.fromisoformat(first_release.rstrip("Z"))
                if age < timedelta(days=30):
                    findings.append({
                        "severity": "HIGH",
                        "message": f"Package is only {age.days} days old",
                    })

        # Check downloads (via pypistats)
        # Check maintainer count
        author = info.get("author", "")
        if not info.get("project_urls"):
            findings.append({
                "severity": "HIGH",
                "message": "No project URLs / repository link",
            })

    return {"package": package_name, "findings": findings}
```

---

## Model Poisoning

### Risk Level: CRITICAL

Malicious models on Hugging Face Hub or other registries that execute arbitrary code on load.

### Attack Vectors

```
1. Pickle-based models (PyTorch .pt/.pth, joblib)
   - __reduce__ method executes code on deserialization
   - Hidden payloads in model weights files

2. Backdoored models
   - Models fine-tuned to produce specific outputs for trigger inputs
   - Appear normal on standard benchmarks

3. Metadata poisoning
   - Malicious code in model cards or config files
   - Modified tokenizer configs with code execution
```

### Dangerous Model Formats

| Format | Risk Level | Reason |
|--------|-----------|--------|
| `.pt`, `.pth` (PyTorch) | CRITICAL | Uses pickle - arbitrary code execution |
| `.pkl`, `.pickle` | CRITICAL | Python pickle - arbitrary code execution |
| `.joblib` | CRITICAL | Uses pickle internally |
| `.h5` (Keras) | HIGH | Can contain Lambda layers with code |
| `.onnx` | LOW | Declarative format, safer |
| `.safetensors` | SAFE | No code execution possible |

### Detection Patterns

```regex
# Unsafe model loading
torch\.load\s*\(
pickle\.loads?\s*\(
joblib\.load\s*\(
keras\.models\.load_model\(

# Unverified model sources
from_pretrained\s*\((?!.*revision=)
from_pretrained\s*\((?!.*trust_remote_code=False)
pipeline\s*\(.*model\s*=\s*['"]((?!gpt|claude|llama).)*['"]

# trust_remote_code enabled
trust_remote_code\s*=\s*True
```

### Safe Model Loading

```python
# ALWAYS prefer safetensors
from safetensors.torch import load_model
model = load_model(model, "model.safetensors")

# If PyTorch, use weights_only
model = torch.load("model.pt", weights_only=True)  # Python 3.12+

# Verify model source
from huggingface_hub import scan_cache_dir
model = AutoModel.from_pretrained(
    "organization/model-name",
    revision="specific-commit-hash",  # Pin to known-good version
    trust_remote_code=False,          # NEVER True for untrusted models
)
```

---

## Dependency Confusion

### Risk Level: HIGH

Attackers publish packages to public registries that shadow internal/private package names.

### AI-Specific Risks

```
1. AI suggests installing non-standard packages
2. Packages with similar names to popular AI libraries
3. Typosquatting on AI package names:
   - langchain vs lang-chain vs langchian
   - openai vs open-ai vs openai-api
   - transformers vs transformer vs huggingface-transformers
```

### Known Risky Package Patterns

```python
SUSPICIOUS_PACKAGE_NAMES = {
    # Packages that don't exist but AI might suggest
    "langchain-community-tools",
    "openai-functions",
    "anthropic-tools",
    "llama-index-tools",
    "chromadb-client",

    # Common typosquatting targets
    "langchian",           # langchain
    "opanai",              # openai
    "antropic",            # anthropic
    "huggingface",         # huggingface-hub
    "llamaindex",          # llama-index
    "pinecone",            # pinecone-client
}
```

---

## MCP Protocol Risks

### Risk Level: HIGH

Model Context Protocol (MCP) introduces new attack surfaces for AI agent systems.

### CVE-2025-54136 (Cursor MCPoison)

Silent and persistent RCE through malicious MCP server configurations.

### Detection Patterns

```regex
# MCP configurations
mcp_server.*url\s*=
mcp.*transport.*stdio
mcp.*command\s*=

# Unverified MCP sources
mcp_servers.*\[(?!.*localhost)
mcp.*remote.*server
```

### Mitigation

```python
# Always verify MCP server sources
ALLOWED_MCP_SERVERS = {
    "localhost:3000",
    "mcp.internal.company.com",
}

def validate_mcp_config(config: dict) -> bool:
    """Validate MCP server configuration."""
    server_url = config.get("url", "")
    parsed = urlparse(server_url)
    if parsed.hostname not in [urlparse(s).hostname for s in ALLOWED_MCP_SERVERS]:
        raise ValueError(f"Untrusted MCP server: {server_url}")
    return True
```

---

## CI/CD Pipeline Threats

### Risk Level: HIGH

AI security risks in the development pipeline.

### Detection Checklist

```
- [ ] AI-generated code reviewed before merge
- [ ] Dependency lockfiles committed (pip freeze / npm lock)
- [ ] No dynamic package installation in CI
- [ ] Model files scanned before deployment
- [ ] Secrets not embedded in AI-generated code
- [ ] Container images scanned for AI component CVEs
```

### GitHub Actions Security Gate Template

```yaml
name: AI Security Gate
on: [pull_request]

jobs:
  ai-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check for hardcoded AI keys
        run: |
          if grep -rE "sk-(proj-|ant-api|or-v1-)[a-zA-Z0-9_-]+" --include="*.py" --include="*.ts" .; then
            echo "::error::Hardcoded AI API keys detected!"
            exit 1
          fi

      - name: Verify dependencies exist
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt

      - name: Check for unsafe model loading
        run: |
          if grep -rE "torch\.load|pickle\.load|trust_remote_code\s*=\s*True" --include="*.py" .; then
            echo "::warning::Potentially unsafe model loading detected"
          fi

      - name: Check for excessive agency
        run: |
          if grep -rE "load_tools.*shell|PythonREPLTool|create_python_agent" --include="*.py" .; then
            echo "::warning::Agent with code execution capabilities detected"
          fi
```

---

## Detection and Prevention Summary

### Priority Matrix

| Threat | Impact | Likelihood | Priority |
|--------|--------|-----------|----------|
| Slopsquatting | HIGH | HIGH | P0 |
| Model poisoning (pickle) | CRITICAL | MEDIUM | P0 |
| MCP server compromise | CRITICAL | MEDIUM | P0 |
| Dependency confusion | HIGH | MEDIUM | P1 |
| Backdoored models | CRITICAL | LOW | P1 |
| CI/CD pipeline injection | HIGH | LOW | P2 |

### Quick Prevention Checklist

```
For every AI-assisted development session:
- [ ] Verify all suggested packages exist on PyPI/npm BEFORE installing
- [ ] Use safetensors format for model files
- [ ] Set trust_remote_code=False when loading models
- [ ] Review AI-generated code for hardcoded credentials
- [ ] Pin dependency versions in lockfiles
- [ ] Use allowlists for MCP servers
- [ ] Enable human-in-the-loop for agent tool calls
```
