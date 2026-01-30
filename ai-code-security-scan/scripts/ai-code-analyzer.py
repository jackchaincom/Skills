#!/usr/bin/env python3
"""
AI Code Security Analyzer

Scans Python codebases for AI/ML security vulnerabilities based on OWASP LLM Top 10:2025.
Detects prompt injection risks, sensitive data exposure, supply chain vulnerabilities,
excessive agency patterns, and AI-specific code weaknesses.

Usage:
    python ai-code-analyzer.py /path/to/project [--output report.json] [--severity HIGH]
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    """Represents a security finding."""
    severity: str
    category: str
    owasp_id: str
    title: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    fix: str


@dataclass
class ScanResult:
    """Aggregated scan results."""
    project_path: str
    scan_time: str
    total_files_scanned: int
    findings: list = field(default_factory=list)
    frameworks_detected: list = field(default_factory=list)


# =============================================================================
# DETECTION PATTERNS - Based on OWASP LLM Top 10:2025
# =============================================================================

PATTERNS = {
    # LLM01: Prompt Injection
    "LLM01": {
        "title": "Prompt Injection",
        "patterns": [
            {
                "name": "User input in f-string prompt",
                "regex": r'f["\'].*\{.*user.*\}.*["\']',
                "severity": "CRITICAL",
                "description": "User input directly interpolated into prompt string",
                "fix": "Use parameterized prompts or sanitize user input",
            },
            {
                "name": "String concatenation in prompt",
                "regex": r'prompt\s*=.*\+.*(?:user|input|request|query)',
                "severity": "CRITICAL",
                "description": "User input concatenated into prompt",
                "fix": "Use ChatPromptTemplate with proper message roles",
            },
            {
                "name": "Format string with user input",
                "regex": r'\.format\s*\(.*(?:user|input|request)',
                "severity": "HIGH",
                "description": "String formatting with user-controlled values",
                "fix": "Validate and sanitize input before formatting",
            },
            {
                "name": "RAG without content validation",
                "regex": r'get_relevant_documents\s*\((?!.*filter)',
                "severity": "HIGH",
                "description": "RAG retrieval without content filtering",
                "fix": "Add content validation for retrieved documents",
            },
        ],
    },
    # LLM02: Sensitive Information Disclosure
    "LLM02": {
        "title": "Sensitive Information Disclosure",
        "patterns": [
            {
                "name": "Logging prompts/responses",
                "regex": r'log(?:ger)?\.(?:info|debug|warning)\s*\(.*(?:prompt|response|message)',
                "severity": "HIGH",
                "description": "Logging LLM prompts or responses may expose sensitive data",
                "fix": "Sanitize logs or use structured logging with PII redaction",
            },
            {
                "name": "Print statement with LLM content",
                "regex": r'print\s*\(.*\.(?:content|text|output)',
                "severity": "MEDIUM",
                "description": "Printing LLM output may expose sensitive data",
                "fix": "Remove debug prints or sanitize output",
            },
            {
                "name": "Exposing system prompt via API",
                "regex": r'return.*system.*prompt',
                "severity": "HIGH",
                "description": "System prompt exposed through API response",
                "fix": "Never expose system prompts in API responses",
            },
            {
                "name": "Unbounded conversation memory",
                "regex": r'ConversationBufferMemory\s*\(\s*\)',
                "severity": "MEDIUM",
                "description": "Unbounded memory accumulates all conversation data",
                "fix": "Use ConversationBufferWindowMemory with k limit",
            },
        ],
    },
    # LLM03: Supply Chain Vulnerabilities
    "LLM03": {
        "title": "Supply Chain Vulnerabilities",
        "patterns": [
            {
                "name": "Unverified model loading",
                "regex": r'from_pretrained\s*\(.*(?:user|input|request|variable)',
                "severity": "CRITICAL",
                "description": "Loading model from user-controlled source enables RCE",
                "fix": "Use model allowlist and verify model sources",
            },
            {
                "name": "Unsafe torch.load",
                "regex": r'torch\.load\s*\(',
                "severity": "CRITICAL",
                "description": "torch.load uses pickle which allows code execution",
                "fix": "Use safetensors or torch.load(..., weights_only=True)",
            },
            {
                "name": "Pickle deserialization",
                "regex": r'pickle\.loads?\s*\(',
                "severity": "CRITICAL",
                "description": "Pickle deserialization allows arbitrary code execution",
                "fix": "Use safetensors or JSON for model data",
            },
            {
                "name": "Joblib load",
                "regex": r'joblib\.load\s*\(',
                "severity": "HIGH",
                "description": "joblib uses pickle internally",
                "fix": "Use safetensors format instead",
            },
            {
                "name": "Dynamic package installation",
                "regex": r'(?:os\.system|subprocess).*pip.*install',
                "severity": "CRITICAL",
                "description": "Dynamic package installation is a slopsquatting target",
                "fix": "Use lockfiles and verify packages exist before install",
            },
            {
                "name": "trust_remote_code enabled",
                "regex": r'trust_remote_code\s*=\s*True',
                "severity": "HIGH",
                "description": "Remote code execution enabled for model loading",
                "fix": "Set trust_remote_code=False for untrusted models",
            },
        ],
    },
    # LLM05: Insecure Output Handling
    "LLM05": {
        "title": "Insecure Output Handling",
        "patterns": [
            {
                "name": "Executing LLM output",
                "regex": r'(?:eval|exec)\s*\(.*\.(?:content|text|output|result)',
                "severity": "CRITICAL",
                "description": "Executing LLM-generated code without sandboxing",
                "fix": "Use sandboxed execution with restricted builtins",
            },
            {
                "name": "LLM output in SQL",
                "regex": r'(?:execute|cursor)\s*\(.*\.(?:content|text|output)',
                "severity": "CRITICAL",
                "description": "LLM output used directly in SQL query",
                "fix": "Use parameterized queries and validate SQL structure",
            },
            {
                "name": "LLM output in shell",
                "regex": r'(?:os\.system|subprocess\.(?:run|call|Popen))\s*\(.*\.(?:content|text|output)',
                "severity": "CRITICAL",
                "description": "LLM output used in shell command",
                "fix": "Never pass LLM output to shell commands",
            },
            {
                "name": "LLM output in template",
                "regex": r'render_template_string\s*\(.*(?:response|output)',
                "severity": "HIGH",
                "description": "LLM output in template enables XSS",
                "fix": "Sanitize output or use safe templates",
            },
        ],
    },
    # LLM06: Excessive Agency
    "LLM06": {
        "title": "Excessive Agency",
        "patterns": [
            {
                "name": "Shell tool loaded",
                "regex": r'load_tools\s*\(.*["\'](?:terminal|shell)["\']',
                "severity": "CRITICAL",
                "description": "Agent has shell command execution capability",
                "fix": "Remove shell tools or require human approval",
            },
            {
                "name": "Python REPL tool",
                "regex": r'(?:PythonREPLTool|create_python_agent)',
                "severity": "CRITICAL",
                "description": "Agent can execute arbitrary Python code",
                "fix": "Use sandboxed execution or remove tool",
            },
            {
                "name": "File management tool",
                "regex": r'load_tools\s*\(.*["\']file["\']',
                "severity": "HIGH",
                "description": "Agent can read/write arbitrary files",
                "fix": "Restrict to specific directories or remove",
            },
            {
                "name": "AgentExecutor without limits",
                "regex": r'AgentExecutor\s*\((?!.*max_iterations)',
                "severity": "HIGH",
                "description": "Agent has no iteration limit",
                "fix": "Set max_iterations and max_execution_time",
            },
            {
                "name": "No human approval callback",
                "regex": r'\.run\s*\(.*(?:user|input).*\)(?!.*callback)',
                "severity": "MEDIUM",
                "description": "Agent runs without human-in-the-loop",
                "fix": "Add HumanApprovalCallbackHandler",
            },
        ],
    },
    # LLM07: System Prompt Leakage
    "LLM07": {
        "title": "System Prompt Leakage",
        "patterns": [
            {
                "name": "Hardcoded system prompt",
                "regex": r'(?:SYSTEM_PROMPT|system_prompt)\s*=\s*["\'\"]{{3}}',
                "severity": "MEDIUM",
                "description": "System prompt hardcoded in source code",
                "fix": "Store prompts in environment variables or secure config",
            },
            {
                "name": "System prompt in response",
                "regex": r'return.*(?:system_prompt|SYSTEM_PROMPT)',
                "severity": "HIGH",
                "description": "System prompt returned in API response",
                "fix": "Never expose system prompts",
            },
        ],
    },
    # LLM10: Unbounded Consumption
    "LLM10": {
        "title": "Unbounded Consumption",
        "patterns": [
            {
                "name": "No max_tokens limit",
                "regex": r'\.create\s*\((?!.*max_tokens)(?!.*max_completion_tokens)',
                "severity": "MEDIUM",
                "description": "No token limit on LLM response",
                "fix": "Set max_tokens to appropriate limit",
            },
            {
                "name": "No timeout configured",
                "regex": r'(?:OpenAI|Anthropic)\s*\((?!.*timeout)',
                "severity": "MEDIUM",
                "description": "No timeout configured for API calls",
                "fix": "Set timeout parameter",
            },
            {
                "name": "Recursive agent calls",
                "regex": r'agent\.(?:run|invoke)\s*\(.*agent\.(?:run|invoke)',
                "severity": "HIGH",
                "description": "Recursive agent calls may cause infinite loops",
                "fix": "Add recursion guards and max depth limits",
            },
        ],
    },
    # AI API Keys (always CRITICAL)
    "SECRETS": {
        "title": "Hardcoded Secrets",
        "patterns": [
            {
                "name": "OpenAI API Key",
                "regex": r'sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}',
                "severity": "CRITICAL",
                "description": "Hardcoded OpenAI API key (legacy format)",
                "fix": "Use environment variables for API keys",
            },
            {
                "name": "OpenAI Project API Key",
                "regex": r'sk-proj-[a-zA-Z0-9_-]{80,}',
                "severity": "CRITICAL",
                "description": "Hardcoded OpenAI project API key",
                "fix": "Use environment variables for API keys",
            },
            {
                "name": "Anthropic API Key",
                "regex": r'sk-ant-api\d{2}-[a-zA-Z0-9_-]{80,}',
                "severity": "CRITICAL",
                "description": "Hardcoded Anthropic API key",
                "fix": "Use environment variables for API keys",
            },
            {
                "name": "HuggingFace Token",
                "regex": r'hf_[a-zA-Z0-9]{34,}',
                "severity": "HIGH",
                "description": "Hardcoded HuggingFace token",
                "fix": "Use environment variables for tokens",
            },
            {
                "name": "OpenRouter API Key",
                "regex": r'sk-or-v1-[a-f0-9]{64}',
                "severity": "CRITICAL",
                "description": "Hardcoded OpenRouter API key",
                "fix": "Use environment variables for API keys",
            },
            {
                "name": "Google AI API Key",
                "regex": r'AIza[0-9A-Za-z_-]{35}',
                "severity": "CRITICAL",
                "description": "Hardcoded Google AI API key",
                "fix": "Use environment variables for API keys",
            },
            {
                "name": "Replicate Token",
                "regex": r'r8_[a-zA-Z0-9]{37}',
                "severity": "HIGH",
                "description": "Hardcoded Replicate token",
                "fix": "Use environment variables for tokens",
            },
        ],
    },
    # AI-Generated Code Weaknesses
    "AI_WEAKNESSES": {
        "title": "AI-Generated Code Weaknesses",
        "patterns": [
            {
                "name": "Broad exception catch",
                "regex": r'except\s+(?:Exception|BaseException)\s*:',
                "severity": "LOW",
                "description": "Overly broad exception handling (common AI pattern)",
                "fix": "Catch specific exceptions",
            },
            {
                "name": "Wildcard CORS",
                "regex": r'(?:allow_origins|origins)\s*=\s*\[\s*["\']?\*["\']?\s*\]',
                "severity": "HIGH",
                "description": "CORS allows all origins",
                "fix": "Specify allowed origins explicitly",
            },
            {
                "name": "Placeholder secret",
                "regex": r'(?:secret|key|password)\s*=\s*["\']?(?:changeme|password|secret|admin|test|default)["\']?',
                "severity": "HIGH",
                "description": "Placeholder secret left in code",
                "fix": "Use strong secrets from environment variables",
            },
            {
                "name": "Debug mode enabled",
                "regex": r'debug\s*=\s*True',
                "severity": "HIGH",
                "description": "Debug mode enabled",
                "fix": "Set debug=False in production",
            },
        ],
    },
}

# Framework detection patterns
FRAMEWORK_PATTERNS = {
    "langchain": r'from langchain|import langchain',
    "llama_index": r'from llama_index|import llama_index',
    "openai": r'from openai|import openai|OpenAI\(',
    "anthropic": r'from anthropic|import anthropic|Anthropic\(',
    "transformers": r'from transformers|import transformers|AutoModel',
    "torch": r'import torch|from torch',
    "tensorflow": r'import tensorflow|from tensorflow',
}


def detect_frameworks(content: str) -> list:
    """Detect AI/ML frameworks used in the code."""
    detected = []
    for framework, pattern in FRAMEWORK_PATTERNS.items():
        if re.search(pattern, content, re.IGNORECASE):
            detected.append(framework)
    return detected


def scan_file(file_path: Path) -> tuple[list, list]:
    """Scan a single file for security issues."""
    findings = []
    frameworks = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return findings, frameworks

    # Detect frameworks
    frameworks = detect_frameworks(content)

    # Scan for patterns
    for owasp_id, category in PATTERNS.items():
        for pattern_def in category["patterns"]:
            regex = pattern_def["regex"]
            try:
                for i, line in enumerate(lines, 1):
                    if re.search(regex, line, re.IGNORECASE):
                        finding = Finding(
                            severity=pattern_def["severity"],
                            category=category["title"],
                            owasp_id=owasp_id,
                            title=pattern_def["name"],
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip()[:200],
                            description=pattern_def["description"],
                            fix=pattern_def["fix"],
                        )
                        findings.append(finding)
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{regex}': {e}", file=sys.stderr)

    return findings, frameworks


def scan_directory(project_path: Path, exclude_dirs: Optional[list] = None) -> ScanResult:
    """Scan entire directory for security issues."""
    if exclude_dirs is None:
        exclude_dirs = ['.venv', 'venv', 'node_modules', '.git', '__pycache__', '.mypy_cache', '.pytest_cache']

    result = ScanResult(
        project_path=str(project_path),
        scan_time=datetime.now().isoformat(),
        total_files_scanned=0,
    )

    all_frameworks = set()

    for root, dirs, files in os.walk(project_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            if file.endswith('.py'):
                file_path = Path(root) / file
                findings, frameworks = scan_file(file_path)
                result.findings.extend(findings)
                all_frameworks.update(frameworks)
                result.total_files_scanned += 1

    result.frameworks_detected = list(all_frameworks)
    return result


def format_console_output(result: ScanResult, min_severity: str = "LOW") -> str:
    """Format scan results for console output."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_severity_level = severity_order.get(min_severity, 4)

    output = []
    output.append("=" * 70)
    output.append("AI CODE SECURITY SCAN RESULTS")
    output.append("=" * 70)
    output.append(f"Project: {result.project_path}")
    output.append(f"Scan Time: {result.scan_time}")
    output.append(f"Files Scanned: {result.total_files_scanned}")
    output.append(f"Frameworks Detected: {', '.join(result.frameworks_detected) or 'None'}")
    output.append("")

    # Filter and sort findings
    filtered = [f for f in result.findings if severity_order.get(f.severity, 4) <= min_severity_level]
    sorted_findings = sorted(filtered, key=lambda x: severity_order.get(x.severity, 4))

    # Summary
    severity_counts = {}
    for f in sorted_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    output.append("SUMMARY")
    output.append("-" * 70)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            output.append(f"  {sev}: {count}")
    output.append(f"  TOTAL: {len(sorted_findings)}")
    output.append("")

    # Findings
    if sorted_findings:
        output.append("FINDINGS")
        output.append("-" * 70)
        for f in sorted_findings:
            output.append(f"[{f.severity}] {f.owasp_id} - {f.category}: {f.title}")
            output.append(f"  File: {f.file_path}:{f.line_number}")
            output.append(f"  Code: {f.code_snippet}")
            output.append(f"  Risk: {f.description}")
            output.append(f"  Fix: {f.fix}")
            output.append("")
    else:
        output.append("No findings at the specified severity level or above.")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description="AI Code Security Analyzer - Scan for OWASP LLM Top 10 vulnerabilities"
    )
    parser.add_argument("path", help="Path to project directory to scan")
    parser.add_argument(
        "--output", "-o",
        help="Output file path (JSON format)",
        default=None
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity level to report (default: LOW)"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format to stdout"
    )
    parser.add_argument(
        "--exclude", "-e",
        nargs="*",
        default=[],
        help="Additional directories to exclude"
    )

    args = parser.parse_args()

    project_path = Path(args.path)
    if not project_path.exists():
        print(f"Error: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)

    exclude_dirs = ['.venv', 'venv', 'node_modules', '.git', '__pycache__', '.mypy_cache', '.pytest_cache']
    exclude_dirs.extend(args.exclude)

    print(f"Scanning {project_path}...", file=sys.stderr)
    result = scan_directory(project_path, exclude_dirs)

    if args.json or args.output:
        # Convert to JSON-serializable format
        json_result = {
            "project_path": result.project_path,
            "scan_time": result.scan_time,
            "total_files_scanned": result.total_files_scanned,
            "frameworks_detected": result.frameworks_detected,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "owasp_id": f.owasp_id,
                    "title": f.title,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "code_snippet": f.code_snippet,
                    "description": f.description,
                    "fix": f.fix,
                }
                for f in result.findings
            ],
        }

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(json_result, f, indent=2)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(json_result, indent=2))
    else:
        print(format_console_output(result, args.severity))

    # Exit code based on findings
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    has_critical_or_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in result.findings
    )

    if has_critical_or_high:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
