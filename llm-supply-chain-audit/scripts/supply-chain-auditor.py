#!/usr/bin/env python3
"""
LLM Supply Chain Auditor

Comprehensive supply chain security auditor for AI/ML projects.
Checks package authenticity, model file security, MCP configurations,
and CI/CD pipeline risks.

Usage:
    python supply-chain-auditor.py /path/to/project [--full] [--json]
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import quote

# Optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class Finding:
    """A supply chain security finding."""
    severity: str
    category: str
    file_path: str
    description: str
    recommendation: str
    evidence: list = field(default_factory=list)


@dataclass
class AuditResult:
    """Complete audit results."""
    project_path: str
    scan_time: str
    findings: list = field(default_factory=list)
    packages_checked: int = 0
    model_files_found: int = 0
    mcp_configs_found: int = 0


# Known hallucinated packages (AI commonly suggests these)
KNOWN_HALLUCINATIONS = {
    "langchain-community-tools",
    "openai-functions",
    "anthropic-tools",
    "llama-index-tools",
    "chromadb-client",
    "langchian",  # typo
    "opanai",     # typo
    "antropic",   # typo
}

# Known legitimate AI/ML packages
LEGITIMATE_PACKAGES = {
    "langchain", "langchain-core", "langchain-community", "langchain-openai",
    "langchain-anthropic", "openai", "anthropic", "transformers", "torch",
    "tensorflow", "huggingface-hub", "chromadb", "pinecone-client",
    "qdrant-client", "weaviate-client", "faiss-cpu", "sentence-transformers",
    "tiktoken", "llama-index", "llama-index-core", "pydantic", "fastapi",
}

# Risky model file extensions
RISKY_MODEL_EXTENSIONS = {".pt", ".pth", ".pkl", ".pickle", ".joblib"}
SAFE_MODEL_EXTENSIONS = {".safetensors", ".onnx", ".gguf"}

# MCP config file names
MCP_CONFIG_FILES = [
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "mcp.json",
    "mcp-config.json",
    "mcp-config.yaml",
    ".claude/mcp.json",
]


def extract_packages_from_requirements(file_path: Path) -> list:
    """Extract package names from requirements.txt."""
    packages = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                if match:
                    packages.append(match.group(1))
    except Exception:
        pass
    return packages


def extract_packages_from_pyproject(file_path: Path) -> list:
    """Extract package names from pyproject.toml."""
    packages = []
    try:
        try:
            import tomllib
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
        except ImportError:
            try:
                import tomli as tomllib
                with open(file_path, "rb") as f:
                    data = tomllib.load(f)
            except ImportError:
                return packages

        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
            if match:
                packages.append(match.group(1))

        optional = data.get("project", {}).get("optional-dependencies", {})
        for group in optional.values():
            for dep in group:
                match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                if match:
                    packages.append(match.group(1))
    except Exception:
        pass
    return packages


def verify_pypi_package(name: str) -> dict:
    """Verify a PyPI package exists and check for risk indicators."""
    result = {
        "name": name,
        "exists": None,
        "risks": [],
        "age_days": None,
        "downloads": None,
    }

    if not HAS_REQUESTS:
        return result

    # Skip known legitimate packages for speed
    if name.lower() in LEGITIMATE_PACKAGES:
        result["exists"] = True
        return result

    # Check for known hallucinations first
    if name.lower() in KNOWN_HALLUCINATIONS:
        result["exists"] = False
        result["risks"].append({
            "level": "CRITICAL",
            "message": "Known AI hallucination / malicious package name",
        })
        return result

    try:
        resp = requests.get(
            f"https://pypi.org/pypi/{quote(name)}/json",
            timeout=10
        )

        if resp.status_code == 404:
            result["exists"] = False
            result["risks"].append({
                "level": "CRITICAL",
                "message": f"Package does NOT exist on PyPI",
            })
            return result

        result["exists"] = True
        data = resp.json()
        info = data.get("info", {})

        # Check package age
        releases = data.get("releases", {})
        if releases:
            dates = []
            for version_files in releases.values():
                for file_info in version_files:
                    upload_time = file_info.get("upload_time")
                    if upload_time:
                        try:
                            dt = datetime.fromisoformat(upload_time.rstrip("Z"))
                            dates.append(dt)
                        except ValueError:
                            pass

            if dates:
                earliest = min(dates)
                age = datetime.now() - earliest
                result["age_days"] = age.days

                if age.days < 7:
                    result["risks"].append({
                        "level": "HIGH",
                        "message": f"Very new package ({age.days} days old)",
                    })
                elif age.days < 30:
                    result["risks"].append({
                        "level": "MEDIUM",
                        "message": f"New package ({age.days} days old)",
                    })

        # Check for project URLs
        if not info.get("project_urls"):
            result["risks"].append({
                "level": "MEDIUM",
                "message": "No repository / project URLs",
            })

        # Check description
        if len(info.get("summary", "")) < 20:
            result["risks"].append({
                "level": "LOW",
                "message": "Minimal package description",
            })

    except Exception as e:
        result["risks"].append({
            "level": "WARNING",
            "message": f"Could not verify: {e}",
        })

    return result


def audit_packages(project_path: Path) -> tuple:
    """Audit all project packages."""
    findings = []
    packages_checked = 0

    # Find all dependency files
    dep_files = []
    for pattern in ["requirements*.txt", "pyproject.toml"]:
        dep_files.extend(project_path.rglob(pattern))

    # Exclude venv directories
    dep_files = [
        f for f in dep_files
        if ".venv" not in str(f) and "venv" not in str(f) and "node_modules" not in str(f)
    ]

    # Extract unique packages
    all_packages = set()
    for dep_file in dep_files:
        if dep_file.name.endswith(".txt"):
            all_packages.update(extract_packages_from_requirements(dep_file))
        elif dep_file.name == "pyproject.toml":
            all_packages.update(extract_packages_from_pyproject(dep_file))

    packages_checked = len(all_packages)
    print(f"  Checking {packages_checked} unique packages...", file=sys.stderr)

    for i, pkg in enumerate(all_packages):
        if (i + 1) % 10 == 0:
            print(f"    {i + 1}/{packages_checked}", file=sys.stderr)

        result = verify_pypi_package(pkg)

        if result["exists"] is False:
            findings.append(Finding(
                severity="CRITICAL",
                category="Slopsquatting",
                file_path="dependency files",
                description=f"Package '{pkg}' does NOT exist on PyPI",
                recommendation="Remove this package - it's likely an AI hallucination",
            ))
        elif result["risks"]:
            for risk in result["risks"]:
                findings.append(Finding(
                    severity=risk["level"],
                    category="Package Risk",
                    file_path="dependency files",
                    description=f"Package '{pkg}': {risk['message']}",
                    recommendation="Verify package legitimacy before using",
                ))

    return findings, packages_checked


def audit_model_files(project_path: Path) -> tuple:
    """Audit model files for risky formats."""
    findings = []
    model_count = 0
    exclude_dirs = {".venv", "venv", "node_modules", ".git", "__pycache__"}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for fname in files:
            ext = Path(fname).suffix.lower()

            if ext in RISKY_MODEL_EXTENSIONS:
                model_count += 1
                fpath = Path(root) / fname
                size_mb = fpath.stat().st_size / (1024 * 1024)

                findings.append(Finding(
                    severity="CRITICAL" if ext in {".pkl", ".pickle"} else "HIGH",
                    category="Model Security",
                    file_path=str(fpath),
                    description=f"Risky model format ({ext}) - {size_mb:.1f} MB",
                    recommendation="Convert to safetensors format",
                ))

            elif ext in SAFE_MODEL_EXTENSIONS:
                model_count += 1
                # Safe format, no finding needed

    return findings, model_count


def audit_code_patterns(project_path: Path) -> list:
    """Audit code for unsafe patterns."""
    findings = []
    exclude_dirs = {".venv", "venv", "node_modules", ".git", "__pycache__"}

    patterns = [
        {
            "regex": r"torch\.load\s*\((?!.*weights_only)",
            "severity": "CRITICAL",
            "category": "Unsafe Model Loading",
            "description": "torch.load() without weights_only=True",
            "recommendation": "Add weights_only=True or use safetensors",
        },
        {
            "regex": r"pickle\.loads?\s*\(",
            "severity": "CRITICAL",
            "category": "Unsafe Deserialization",
            "description": "Direct pickle deserialization",
            "recommendation": "Use safe serialization format",
        },
        {
            "regex": r"trust_remote_code\s*=\s*True",
            "severity": "CRITICAL",
            "category": "Remote Code Execution",
            "description": "Remote code execution enabled for model loading",
            "recommendation": "Set trust_remote_code=False",
        },
        {
            "regex": r"from_pretrained\s*\([^)]*\)(?!.*revision=)",
            "severity": "MEDIUM",
            "category": "Unpinned Model",
            "description": "Model loading without pinned revision",
            "recommendation": "Pin to specific commit with revision=",
        },
        {
            "regex": r'pip\s+install\s+["\']?\$',
            "severity": "HIGH",
            "category": "Dynamic Installation",
            "description": "Dynamic package installation from variable",
            "recommendation": "Use lockfiles and verify packages exist",
        },
    ]

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for fname in files:
            if not fname.endswith(".py"):
                continue

            fpath = Path(root) / fname
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                lines = content.split("\n")

                for pattern in patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern["regex"], line):
                            findings.append(Finding(
                                severity=pattern["severity"],
                                category=pattern["category"],
                                file_path=f"{fpath}:{i}",
                                description=pattern["description"],
                                recommendation=pattern["recommendation"],
                                evidence=[line.strip()[:200]],
                            ))
            except Exception:
                continue

    return findings


def audit_mcp_configs(project_path: Path) -> tuple:
    """Audit MCP configuration files."""
    findings = []
    mcp_count = 0

    for config_name in MCP_CONFIG_FILES:
        config_path = project_path / config_name
        if not config_path.exists():
            continue

        mcp_count += 1

        try:
            content = config_path.read_text()

            # Check for remote servers
            remote_servers = re.findall(
                r'"url"\s*:\s*"(https?://(?!localhost|127\.0\.0\.1)[^"]+)"',
                content
            )
            for url in remote_servers:
                findings.append(Finding(
                    severity="HIGH",
                    category="MCP Remote Server",
                    file_path=str(config_path),
                    description=f"Remote MCP server: {url}",
                    recommendation="Verify server trustworthiness and add to allowlist",
                ))

            # Check for npx with unknown packages
            npx_packages = re.findall(
                r'"command"\s*:\s*"npx".*?"args"\s*:\s*\[\s*"([^"]+)"',
                content, re.DOTALL
            )
            for pkg in npx_packages:
                if not pkg.startswith("@modelcontextprotocol/"):
                    findings.append(Finding(
                        severity="HIGH",
                        category="MCP Unknown Package",
                        file_path=str(config_path),
                        description=f"npx running unverified package: {pkg}",
                        recommendation="Verify package legitimacy before using",
                    ))

            # Check for shell commands
            if re.search(r'"command"\s*:\s*"(bash|sh|cmd|powershell)"', content):
                findings.append(Finding(
                    severity="CRITICAL",
                    category="MCP Shell Command",
                    file_path=str(config_path),
                    description="MCP server uses direct shell execution",
                    recommendation="Remove or sandbox shell-based MCP servers",
                ))

        except Exception:
            pass

    return findings, mcp_count


def format_console_output(result: AuditResult) -> str:
    """Format audit results for console."""
    output = []
    output.append("=" * 70)
    output.append("LLM SUPPLY CHAIN AUDIT RESULTS")
    output.append("=" * 70)
    output.append(f"Project: {result.project_path}")
    output.append(f"Scan Time: {result.scan_time}")
    output.append(f"Packages Checked: {result.packages_checked}")
    output.append(f"Model Files Found: {result.model_files_found}")
    output.append(f"MCP Configs Found: {result.mcp_configs_found}")

    # Summary
    severity_counts = {}
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    output.append("\nSUMMARY")
    output.append("-" * 70)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            output.append(f"  {sev}: {count}")
    output.append(f"  TOTAL: {len(result.findings)}")

    # Group by category
    categories = {}
    for f in result.findings:
        if f.category not in categories:
            categories[f.category] = []
        categories[f.category].append(f)

    # Output by category
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "WARNING": 4}

    for category, findings in sorted(categories.items()):
        output.append(f"\n{category.upper()}")
        output.append("-" * 70)
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity, 4))
        for f in sorted_findings:
            output.append(f"\n[{f.severity}] {f.description}")
            output.append(f"  File: {f.file_path}")
            output.append(f"  Fix: {f.recommendation}")
            if f.evidence:
                output.append(f"  Evidence: {f.evidence[0][:100]}...")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description="LLM Supply Chain Auditor - Comprehensive AI/ML supply chain security"
    )
    parser.add_argument("path", help="Path to project directory to audit")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Full audit including online package verification"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path"
    )
    parser.add_argument(
        "--skip-packages",
        action="store_true",
        help="Skip package verification (faster)"
    )

    args = parser.parse_args()

    project_path = Path(args.path)
    if not project_path.exists():
        print(f"Error: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)

    result = AuditResult(
        project_path=str(project_path),
        scan_time=datetime.now().isoformat(),
    )

    print("LLM Supply Chain Audit", file=sys.stderr)
    print("=" * 40, file=sys.stderr)

    # Audit packages
    if not args.skip_packages:
        print("\n1. Auditing packages...", file=sys.stderr)
        pkg_findings, pkg_count = audit_packages(project_path)
        result.findings.extend(pkg_findings)
        result.packages_checked = pkg_count

    # Audit model files
    print("\n2. Auditing model files...", file=sys.stderr)
    model_findings, model_count = audit_model_files(project_path)
    result.findings.extend(model_findings)
    result.model_files_found = model_count

    # Audit code patterns
    print("\n3. Auditing code patterns...", file=sys.stderr)
    code_findings = audit_code_patterns(project_path)
    result.findings.extend(code_findings)

    # Audit MCP configs
    print("\n4. Auditing MCP configurations...", file=sys.stderr)
    mcp_findings, mcp_count = audit_mcp_configs(project_path)
    result.findings.extend(mcp_findings)
    result.mcp_configs_found = mcp_count

    print("\nAudit complete!", file=sys.stderr)

    # Output results
    if args.json or args.output:
        json_result = {
            "project_path": result.project_path,
            "scan_time": result.scan_time,
            "packages_checked": result.packages_checked,
            "model_files_found": result.model_files_found,
            "mcp_configs_found": result.mcp_configs_found,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "file_path": f.file_path,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
        }

        if args.output:
            with open(args.output, "w") as f:
                json.dump(json_result, f, indent=2)
            print(f"\nResults written to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(json_result, indent=2))
    else:
        print(format_console_output(result))

    # Exit code
    critical_high = sum(
        1 for f in result.findings if f.severity in ("CRITICAL", "HIGH")
    )
    if critical_high > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
