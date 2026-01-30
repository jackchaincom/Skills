#!/usr/bin/env python3
"""
Hallucinated Package Detector

Detects potentially malicious packages that may have been suggested by AI assistants
(slopsquatting attacks). Checks if packages exist, their age, download counts,
and similarity to popular packages.

Usage:
    python hallucination-detector.py /path/to/project [--check-npm] [--strict]
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import quote

# Optional dependencies - graceful degradation
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: 'requests' not installed. Online verification disabled.", file=sys.stderr)


@dataclass
class PackageInfo:
    """Information about a package."""
    name: str
    source: str  # requirements.txt, pyproject.toml, package.json
    registry: str  # pypi, npm
    exists: Optional[bool] = None
    age_days: Optional[int] = None
    weekly_downloads: Optional[int] = None
    description: Optional[str] = None
    repository_url: Optional[str] = None
    maintainer_count: Optional[int] = None
    risk_level: str = "UNKNOWN"
    risk_reasons: list = None

    def __post_init__(self):
        if self.risk_reasons is None:
            self.risk_reasons = []


# Known legitimate packages that might trigger false positives
KNOWN_LEGITIMATE = {
    "pypi": {
        "langchain", "langchain-core", "langchain-community", "langchain-openai",
        "langchain-anthropic", "langchain-google-genai", "llama-index", "llama-index-core",
        "openai", "anthropic", "transformers", "torch", "tensorflow", "huggingface-hub",
        "chromadb", "pinecone-client", "weaviate-client", "qdrant-client", "faiss-cpu",
        "sentence-transformers", "tiktoken", "pypdf", "unstructured", "pydantic",
        "fastapi", "uvicorn", "pytest", "requests", "httpx", "aiohttp",
    },
    "npm": {
        "langchain", "@langchain/core", "@langchain/openai", "@langchain/anthropic",
        "openai", "@anthropic-ai/sdk", "llamaindex", "chromadb", "pinecone",
        "react", "next", "vue", "svelte", "express", "fastify", "axios",
    },
}

# Packages that don't exist but AI commonly hallucinates
KNOWN_HALLUCINATIONS = {
    "pypi": {
        "langchain-community-tools",
        "openai-functions",
        "anthropic-tools",
        "llama-index-tools",
        "chromadb-client",
        "langchian",  # typo
        "opanai",  # typo
        "antropic",  # typo
        "huggingface",  # wrong name (should be huggingface-hub)
        "llamaindex",  # wrong name (should be llama-index)
        "pinecone",  # wrong name (should be pinecone-client)
    },
    "npm": {
        "@chatgptclaude_club/claude-code",  # Malicious impersonation
        "langchain-tools",
        "openai-helpers",
        "anthropic-utils",
    },
}

# Popular packages for Levenshtein distance comparison
POPULAR_PACKAGES = {
    "pypi": [
        "langchain", "openai", "anthropic", "transformers", "torch",
        "tensorflow", "pandas", "numpy", "requests", "flask", "django",
        "fastapi", "pydantic", "pytest", "boto3", "sqlalchemy",
    ],
    "npm": [
        "react", "vue", "angular", "express", "axios", "lodash",
        "moment", "typescript", "webpack", "babel", "eslint", "prettier",
    ],
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def extract_packages_from_requirements(file_path: Path) -> list:
    """Extract package names from requirements.txt."""
    packages = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Extract package name (before any version specifier)
                match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                if match:
                    packages.append(PackageInfo(
                        name=match.group(1),
                        source=str(file_path),
                        registry="pypi"
                    ))
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
    return packages


def extract_packages_from_pyproject(file_path: Path) -> list:
    """Extract package names from pyproject.toml."""
    packages = []
    try:
        # Try tomllib (Python 3.11+) or tomli
        try:
            import tomllib
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
        except ImportError:
            try:
                import tomli
                with open(file_path, 'rb') as f:
                    data = tomli.load(f)
            except ImportError:
                # Fallback: simple regex parsing
                with open(file_path, 'r') as f:
                    content = f.read()
                # Find dependencies section
                deps_match = re.search(r'\[(?:project\.)?dependencies\]\s*\n((?:[^\[]*\n)*)', content)
                if deps_match:
                    for line in deps_match.group(1).split('\n'):
                        match = re.match(r'^([a-zA-Z0-9_-]+)', line.strip())
                        if match:
                            packages.append(PackageInfo(
                                name=match.group(1),
                                source=str(file_path),
                                registry="pypi"
                            ))
                return packages

        # Extract from parsed TOML
        deps = data.get('project', {}).get('dependencies', [])
        if isinstance(deps, list):
            for dep in deps:
                match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                if match:
                    packages.append(PackageInfo(
                        name=match.group(1),
                        source=str(file_path),
                        registry="pypi"
                    ))

        # Also check optional dependencies
        optional = data.get('project', {}).get('optional-dependencies', {})
        for group_deps in optional.values():
            for dep in group_deps:
                match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                if match:
                    packages.append(PackageInfo(
                        name=match.group(1),
                        source=str(file_path),
                        registry="pypi"
                    ))

    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
    return packages


def extract_packages_from_package_json(file_path: Path) -> list:
    """Extract package names from package.json."""
    packages = []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)

        for section in ['dependencies', 'devDependencies', 'peerDependencies']:
            deps = data.get(section, {})
            for name in deps.keys():
                packages.append(PackageInfo(
                    name=name,
                    source=str(file_path),
                    registry="npm"
                ))
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
    return packages


def check_pypi_package(package: PackageInfo) -> PackageInfo:
    """Check if a PyPI package exists and gather metadata."""
    if not HAS_REQUESTS:
        return package

    try:
        url = f"https://pypi.org/pypi/{quote(package.name)}/json"
        resp = requests.get(url, timeout=10)

        if resp.status_code == 404:
            package.exists = False
            package.risk_level = "CRITICAL"
            package.risk_reasons.append("Package does not exist on PyPI - possible AI hallucination")
            return package

        if resp.status_code != 200:
            package.risk_reasons.append(f"Could not verify package (HTTP {resp.status_code})")
            return package

        package.exists = True
        data = resp.json()
        info = data.get('info', {})

        # Get description
        package.description = info.get('summary', '')[:200]

        # Get repository URL
        urls = info.get('project_urls', {})
        package.repository_url = urls.get('Source') or urls.get('Repository') or urls.get('Homepage')

        # Calculate age
        releases = data.get('releases', {})
        if releases:
            first_release_dates = []
            for version_releases in releases.values():
                for release in version_releases:
                    upload_time = release.get('upload_time')
                    if upload_time:
                        first_release_dates.append(upload_time)

            if first_release_dates:
                oldest = min(first_release_dates)
                try:
                    release_date = datetime.fromisoformat(oldest.rstrip('Z'))
                    package.age_days = (datetime.now() - release_date).days
                except ValueError:
                    pass

        # Check risk indicators
        assess_package_risk(package, "pypi")

    except requests.RequestException as e:
        package.risk_reasons.append(f"Network error checking package: {e}")
    except Exception as e:
        package.risk_reasons.append(f"Error checking package: {e}")

    return package


def check_npm_package(package: PackageInfo) -> PackageInfo:
    """Check if an npm package exists and gather metadata."""
    if not HAS_REQUESTS:
        return package

    try:
        # Handle scoped packages (@org/name)
        encoded_name = quote(package.name, safe='@')
        url = f"https://registry.npmjs.org/{encoded_name}"
        resp = requests.get(url, timeout=10)

        if resp.status_code == 404:
            package.exists = False
            package.risk_level = "CRITICAL"
            package.risk_reasons.append("Package does not exist on npm - possible AI hallucination")
            return package

        if resp.status_code != 200:
            package.risk_reasons.append(f"Could not verify package (HTTP {resp.status_code})")
            return package

        package.exists = True
        data = resp.json()

        # Get description
        package.description = data.get('description', '')[:200]

        # Get repository URL
        repo = data.get('repository', {})
        if isinstance(repo, dict):
            package.repository_url = repo.get('url', '')
        elif isinstance(repo, str):
            package.repository_url = repo

        # Get creation date
        time_info = data.get('time', {})
        created = time_info.get('created')
        if created:
            try:
                release_date = datetime.fromisoformat(created.rstrip('Z'))
                package.age_days = (datetime.now() - release_date).days
            except ValueError:
                pass

        # Check risk indicators
        assess_package_risk(package, "npm")

    except requests.RequestException as e:
        package.risk_reasons.append(f"Network error checking package: {e}")
    except Exception as e:
        package.risk_reasons.append(f"Error checking package: {e}")

    return package


def assess_package_risk(package: PackageInfo, registry: str) -> None:
    """Assess risk level based on gathered metadata."""
    risk_score = 0

    # Skip known legitimate packages
    if package.name.lower() in KNOWN_LEGITIMATE.get(registry, set()):
        package.risk_level = "SAFE"
        package.risk_reasons.append("Known legitimate package")
        return

    # Check if known hallucination
    if package.name.lower() in KNOWN_HALLUCINATIONS.get(registry, set()):
        package.risk_level = "CRITICAL"
        package.risk_reasons.append("Known AI hallucination or malicious package")
        return

    # Age check (< 30 days is suspicious)
    if package.age_days is not None:
        if package.age_days < 7:
            risk_score += 40
            package.risk_reasons.append(f"Very new package (only {package.age_days} days old)")
        elif package.age_days < 30:
            risk_score += 25
            package.risk_reasons.append(f"New package ({package.age_days} days old)")
        elif package.age_days < 90:
            risk_score += 10
            package.risk_reasons.append(f"Relatively new package ({package.age_days} days old)")

    # Repository URL check
    if not package.repository_url:
        risk_score += 20
        package.risk_reasons.append("No repository URL provided")

    # Description check
    if not package.description or len(package.description) < 20:
        risk_score += 15
        package.risk_reasons.append("Missing or minimal description")

    # Name similarity to popular packages (typosquatting)
    popular = POPULAR_PACKAGES.get(registry, [])
    for popular_pkg in popular:
        if popular_pkg != package.name.lower():
            distance = levenshtein_distance(package.name.lower(), popular_pkg)
            if distance == 1:
                risk_score += 30
                package.risk_reasons.append(f"Name very similar to popular package '{popular_pkg}' (possible typosquatting)")
                break
            elif distance == 2:
                risk_score += 15
                package.risk_reasons.append(f"Name similar to popular package '{popular_pkg}'")
                break

    # Determine risk level
    if risk_score >= 50:
        package.risk_level = "HIGH"
    elif risk_score >= 30:
        package.risk_level = "MEDIUM"
    elif risk_score >= 10:
        package.risk_level = "LOW"
    else:
        package.risk_level = "SAFE"


def scan_project(project_path: Path, check_npm: bool = False) -> list:
    """Scan project for dependency files and check packages."""
    packages = []

    # Find requirements.txt files
    for req_file in project_path.rglob('requirements*.txt'):
        if '.venv' not in str(req_file) and 'node_modules' not in str(req_file):
            packages.extend(extract_packages_from_requirements(req_file))

    # Find pyproject.toml
    for pyproject in project_path.rglob('pyproject.toml'):
        if '.venv' not in str(pyproject) and 'node_modules' not in str(pyproject):
            packages.extend(extract_packages_from_pyproject(pyproject))

    # Find package.json if npm check enabled
    if check_npm:
        for pkg_json in project_path.rglob('package.json'):
            if 'node_modules' not in str(pkg_json):
                packages.extend(extract_packages_from_package_json(pkg_json))

    # Deduplicate by name and registry
    seen = set()
    unique_packages = []
    for pkg in packages:
        key = (pkg.name.lower(), pkg.registry)
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)

    # Check each package
    print(f"Checking {len(unique_packages)} unique packages...", file=sys.stderr)
    for i, pkg in enumerate(unique_packages):
        if pkg.registry == "pypi":
            check_pypi_package(pkg)
        elif pkg.registry == "npm":
            check_npm_package(pkg)

        if (i + 1) % 10 == 0:
            print(f"  Checked {i + 1}/{len(unique_packages)} packages", file=sys.stderr)

    return unique_packages


def format_console_output(packages: list, strict: bool = False) -> str:
    """Format results for console output."""
    output = []
    output.append("=" * 70)
    output.append("HALLUCINATED PACKAGE DETECTION RESULTS")
    output.append("=" * 70)

    # Group by risk level
    risk_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "SAFE": [], "UNKNOWN": []}
    for pkg in packages:
        risk_groups[pkg.risk_level].append(pkg)

    # Summary
    output.append("\nSUMMARY")
    output.append("-" * 70)
    output.append(f"Total packages scanned: {len(packages)}")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        count = len(risk_groups[level])
        if count > 0:
            output.append(f"  {level}: {count}")

    # Critical and High findings
    suspicious = risk_groups["CRITICAL"] + risk_groups["HIGH"]
    if strict:
        suspicious += risk_groups["MEDIUM"]

    if suspicious:
        output.append("\nSUSPICIOUS PACKAGES")
        output.append("-" * 70)
        for pkg in suspicious:
            output.append(f"\n[{pkg.risk_level}] {pkg.name} ({pkg.registry})")
            output.append(f"  Source: {pkg.source}")
            if pkg.exists is False:
                output.append("  Status: DOES NOT EXIST!")
            elif pkg.exists is True:
                output.append(f"  Exists: Yes (age: {pkg.age_days or 'unknown'} days)")
            if pkg.description:
                output.append(f"  Description: {pkg.description[:100]}...")
            if pkg.repository_url:
                output.append(f"  Repository: {pkg.repository_url}")
            if pkg.risk_reasons:
                output.append("  Risk factors:")
                for reason in pkg.risk_reasons:
                    output.append(f"    - {reason}")
    else:
        output.append("\nNo suspicious packages found.")

    # Non-existent packages (most critical)
    non_existent = [p for p in packages if p.exists is False]
    if non_existent:
        output.append("\n" + "!" * 70)
        output.append("WARNING: The following packages DO NOT EXIST!")
        output.append("These are likely AI hallucinations and should be removed:")
        output.append("!" * 70)
        for pkg in non_existent:
            output.append(f"  - {pkg.name} (from {pkg.source})")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description="Hallucinated Package Detector - Find AI-suggested malicious packages"
    )
    parser.add_argument("path", help="Path to project directory to scan")
    parser.add_argument(
        "--check-npm",
        action="store_true",
        help="Also check npm packages in package.json"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat MEDIUM risk packages as suspicious"
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

    args = parser.parse_args()

    project_path = Path(args.path)
    if not project_path.exists():
        print(f"Error: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)

    packages = scan_project(project_path, args.check_npm)

    if args.json or args.output:
        json_result = {
            "scan_time": datetime.now().isoformat(),
            "project_path": str(project_path),
            "total_packages": len(packages),
            "packages": [
                {
                    "name": p.name,
                    "source": p.source,
                    "registry": p.registry,
                    "exists": p.exists,
                    "age_days": p.age_days,
                    "description": p.description,
                    "repository_url": p.repository_url,
                    "risk_level": p.risk_level,
                    "risk_reasons": p.risk_reasons,
                }
                for p in packages
            ],
        }

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(json_result, f, indent=2)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(json_result, indent=2))
    else:
        print(format_console_output(packages, args.strict))

    # Exit code based on findings
    non_existent = [p for p in packages if p.exists is False]
    high_risk = [p for p in packages if p.risk_level in ("CRITICAL", "HIGH")]

    if non_existent or high_risk:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
