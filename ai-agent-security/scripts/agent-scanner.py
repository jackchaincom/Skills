#!/usr/bin/env python3
"""
AI Agent Security Scanner

Scans codebases for AI agent security vulnerabilities including:
- Excessive agency (OWASP LLM06)
- Unsafe tool configurations
- Missing permission boundaries
- Agent loop vulnerabilities
- Prompt injection risks in agent contexts

Usage:
    python agent-scanner.py /path/to/project [--json] [--output file]
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict


@dataclass
class AgentFinding:
    """A security finding related to AI agent implementation."""
    severity: str
    category: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    owasp_id: Optional[str] = None


@dataclass
class ScanResult:
    """Results of agent security scan."""
    project_path: str
    scan_time: str
    total_files_scanned: int
    findings: List[AgentFinding] = field(default_factory=list)
    frameworks_detected: List[str] = field(default_factory=list)
    agents_found: int = 0
    tools_found: int = 0


# Agent framework detection patterns
FRAMEWORK_PATTERNS = {
    "langchain": [
        r"from\s+langchain\.agents\s+import",
        r"from\s+langchain_core\.agents\s+import",
        r"AgentExecutor",
        r"create_openai_functions_agent",
        r"initialize_agent",
    ],
    "llama_index": [
        r"from\s+llama_index\.agent\s+import",
        r"OpenAIAgent",
        r"ReActAgent",
    ],
    "crewai": [
        r"from\s+crewai\s+import",
        r"class\s+\w+\(Agent\)",
    ],
    "autogpt": [
        r"class\s+\w+Agent\s*:",
        r"def\s+run\s*\(\s*self\s*,\s*goals",
    ],
    "semantic_kernel": [
        r"from\s+semantic_kernel",
        r"SKContext",
    ],
}

# Security vulnerability patterns
VULNERABILITY_PATTERNS = {
    # LLM06: Excessive Agency
    "excessive_agency": {
        "patterns": [
            {
                "regex": r"@tool\s*\n\s*def\s+\w+\([^)]*\)\s*.*?subprocess\.(run|call|Popen)",
                "severity": "CRITICAL",
                "description": "Tool with unrestricted subprocess execution",
                "recommendation": "Remove subprocess access or use a sandboxed environment",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"@tool\s*\n\s*def\s+\w+\([^)]*\)\s*.*?os\.(system|popen|exec)",
                "severity": "CRITICAL",
                "description": "Tool with OS command execution capability",
                "recommendation": "Remove OS command access or use strict allowlisting",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"@tool\s*\n\s*def\s+\w+\([^)]*\)\s*.*?(exec|eval)\s*\(",
                "severity": "CRITICAL",
                "description": "Tool with dynamic code execution (exec/eval)",
                "recommendation": "Remove dynamic code execution; use RestrictedPython if needed",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"tools\s*=\s*\[[^\]]*delete[^\]]*\]",
                "severity": "HIGH",
                "description": "Agent has access to delete operations",
                "recommendation": "Review if delete capability is necessary; add confirmation steps",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"allow_dangerous_requests\s*=\s*True",
                "severity": "HIGH",
                "description": "Dangerous requests explicitly allowed",
                "recommendation": "Set allow_dangerous_requests=False",
                "owasp_id": "LLM06",
            },
        ],
    },

    # Tool Security
    "tool_security": {
        "patterns": [
            {
                "regex": r"def\s+\w+\([^)]*path[^)]*\).*?open\s*\(\s*path",
                "severity": "HIGH",
                "description": "Tool with unrestricted file path access",
                "recommendation": "Implement path allowlisting to restrict file access",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"def\s+\w+\([^)]*url[^)]*\).*?requests\.(get|post)",
                "severity": "MEDIUM",
                "description": "Tool with unrestricted URL access",
                "recommendation": "Implement URL allowlisting for network requests",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"def\s+\w+\([^)]*query[^)]*\).*?execute\s*\(\s*query",
                "severity": "HIGH",
                "description": "Tool with raw SQL execution",
                "recommendation": "Use parameterized queries to prevent SQL injection",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"@tool\s*\n\s*def\s+\w+\([^)]*\)\s*.*?pickle\.loads?",
                "severity": "CRITICAL",
                "description": "Tool with pickle deserialization",
                "recommendation": "Replace pickle with safe serialization (JSON, safetensors)",
                "owasp_id": "LLM03",
            },
        ],
    },

    # Agent Configuration
    "agent_config": {
        "patterns": [
            {
                "regex": r"AgentExecutor\s*\([^)]*(?!max_iterations)[^)]*\)",
                "severity": "HIGH",
                "description": "AgentExecutor without max_iterations limit",
                "recommendation": "Add max_iterations parameter to prevent runaway agents",
                "owasp_id": "LLM10",
            },
            {
                "regex": r"AgentExecutor\s*\([^)]*(?!max_execution_time)[^)]*\)",
                "severity": "MEDIUM",
                "description": "AgentExecutor without execution timeout",
                "recommendation": "Add max_execution_time parameter",
                "owasp_id": "LLM10",
            },
            {
                "regex": r"verbose\s*=\s*True",
                "severity": "LOW",
                "description": "Verbose logging enabled (may leak sensitive data)",
                "recommendation": "Set verbose=False in production",
                "owasp_id": "LLM02",
            },
            {
                "regex": r"handle_parsing_errors\s*=\s*False",
                "severity": "MEDIUM",
                "description": "Parsing errors not handled gracefully",
                "recommendation": "Set handle_parsing_errors=True",
                "owasp_id": "LLM05",
            },
        ],
    },

    # Prompt Injection Defense
    "prompt_injection": {
        "patterns": [
            {
                "regex": r"(system_message|system_prompt)\s*=\s*f['\"]",
                "severity": "HIGH",
                "description": "System prompt constructed with f-string (injection risk)",
                "recommendation": "Use static system prompts; validate dynamic content",
                "owasp_id": "LLM01",
            },
            {
                "regex": r"prompt\s*\+\s*user_input",
                "severity": "HIGH",
                "description": "Direct concatenation of user input to prompt",
                "recommendation": "Use prompt templates with proper escaping",
                "owasp_id": "LLM01",
            },
            {
                "regex": r"\.format\s*\(\s*\*\*.*user",
                "severity": "HIGH",
                "description": "User data in format string expansion",
                "recommendation": "Validate and sanitize user input before formatting",
                "owasp_id": "LLM01",
            },
        ],
    },

    # Memory Security
    "memory_security": {
        "patterns": [
            {
                "regex": r"ConversationBufferMemory\s*\(\s*\)",
                "severity": "MEDIUM",
                "description": "Unbounded conversation memory (resource exhaustion risk)",
                "recommendation": "Use ConversationSummaryMemory or set max_token_limit",
                "owasp_id": "LLM10",
            },
            {
                "regex": r"memory\s*=\s*\{\s*\}",
                "severity": "LOW",
                "description": "Unstructured memory storage",
                "recommendation": "Use typed memory stores with validation",
                "owasp_id": "LLM04",
            },
        ],
    },

    # Multi-Agent Security
    "multi_agent": {
        "patterns": [
            {
                "regex": r"allow_delegation\s*=\s*True",
                "severity": "MEDIUM",
                "description": "Agent delegation enabled without restrictions",
                "recommendation": "Implement delegation policies and trust levels",
                "owasp_id": "LLM06",
            },
            {
                "regex": r"\.send\s*\([^)]*agent[^)]*\)",
                "severity": "LOW",
                "description": "Inter-agent message passing detected",
                "recommendation": "Ensure message validation and signing",
                "owasp_id": "LLM06",
            },
        ],
    },

    # Trust Remote Code
    "remote_code": {
        "patterns": [
            {
                "regex": r"trust_remote_code\s*=\s*True",
                "severity": "CRITICAL",
                "description": "Remote code execution enabled",
                "recommendation": "Set trust_remote_code=False unless absolutely necessary",
                "owasp_id": "LLM03",
            },
            {
                "regex": r"run_manager\.on_tool_start.*user",
                "severity": "MEDIUM",
                "description": "User input passed directly to tool callbacks",
                "recommendation": "Validate and sanitize user input in callbacks",
                "owasp_id": "LLM01",
            },
        ],
    },
}


def detect_frameworks(content: str) -> List[str]:
    """Detect which agent frameworks are used."""
    detected = []
    for framework, patterns in FRAMEWORK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content):
                if framework not in detected:
                    detected.append(framework)
                break
    return detected


def count_agents_and_tools(content: str) -> tuple:
    """Count agent and tool definitions."""
    # Count agents
    agent_patterns = [
        r"class\s+\w+Agent",
        r"def\s+create_\w*agent",
        r"Agent\s*\(",
        r"AgentExecutor\s*\(",
    ]
    agents = 0
    for pattern in agent_patterns:
        agents += len(re.findall(pattern, content))

    # Count tools
    tool_patterns = [
        r"@tool",
        r"def\s+\w+_tool\s*\(",
        r"Tool\s*\(",
        r"StructuredTool\s*\(",
    ]
    tools = 0
    for pattern in tool_patterns:
        tools += len(re.findall(pattern, content))

    return agents, tools


def scan_file(file_path: Path, content: str) -> List[AgentFinding]:
    """Scan a single file for agent security vulnerabilities."""
    findings = []
    lines = content.split('\n')

    for category, config in VULNERABILITY_PATTERNS.items():
        for pattern_config in config["patterns"]:
            pattern = pattern_config["regex"]

            # Search for pattern
            for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                # Find line number
                start_pos = match.start()
                line_number = content[:start_pos].count('\n') + 1

                # Get code snippet (context around match)
                start_line = max(0, line_number - 2)
                end_line = min(len(lines), line_number + 3)
                snippet = '\n'.join(lines[start_line:end_line])

                finding = AgentFinding(
                    severity=pattern_config["severity"],
                    category=category,
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=snippet[:500],
                    description=pattern_config["description"],
                    recommendation=pattern_config["recommendation"],
                    owasp_id=pattern_config.get("owasp_id"),
                )
                findings.append(finding)

    return findings


def scan_directory(project_path: Path) -> ScanResult:
    """Scan directory for agent security vulnerabilities."""
    result = ScanResult(
        project_path=str(project_path),
        scan_time=datetime.now().isoformat(),
        total_files_scanned=0,
    )

    # Directories to skip
    skip_dirs = {".venv", "venv", "node_modules", ".git", "__pycache__",
                 ".mypy_cache", ".pytest_cache", "dist", "build"}

    all_frameworks = set()
    total_agents = 0
    total_tools = 0

    for root, dirs, files in os.walk(project_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in files:
            if not fname.endswith('.py'):
                continue

            file_path = Path(root) / fname
            result.total_files_scanned += 1

            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')

                # Detect frameworks
                frameworks = detect_frameworks(content)
                all_frameworks.update(frameworks)

                # Count agents and tools
                agents, tools = count_agents_and_tools(content)
                total_agents += agents
                total_tools += tools

                # Only scan files with agent-related code
                if frameworks or agents > 0 or tools > 0:
                    findings = scan_file(file_path, content)
                    result.findings.extend(findings)

            except Exception as e:
                print(f"Warning: Could not scan {file_path}: {e}", file=sys.stderr)

    result.frameworks_detected = list(all_frameworks)
    result.agents_found = total_agents
    result.tools_found = total_tools

    return result


def format_console_output(result: ScanResult) -> str:
    """Format scan results for console output."""
    output = []
    output.append("=" * 70)
    output.append("AI AGENT SECURITY SCAN RESULTS")
    output.append("=" * 70)

    # Summary
    output.append(f"\nProject: {result.project_path}")
    output.append(f"Scan time: {result.scan_time}")
    output.append(f"Files scanned: {result.total_files_scanned}")
    output.append(f"Frameworks detected: {', '.join(result.frameworks_detected) or 'None'}")
    output.append(f"Agent definitions found: {result.agents_found}")
    output.append(f"Tool definitions found: {result.tools_found}")

    # Severity counts
    severity_counts = {}
    for finding in result.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    output.append("\nFindings by severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            output.append(f"  {sev}: {count}")

    # Detailed findings
    if result.findings:
        output.append("\n" + "-" * 70)
        output.append("DETAILED FINDINGS")
        output.append("-" * 70)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.get(f.severity, 4)
        )

        for finding in sorted_findings:
            output.append(f"\n[{finding.severity}] {finding.description}")
            output.append(f"  Category: {finding.category}")
            output.append(f"  Location: {finding.file_path}:{finding.line_number}")
            if finding.owasp_id:
                output.append(f"  OWASP: {finding.owasp_id}")
            output.append(f"  Fix: {finding.recommendation}")
            output.append(f"  Code:\n    {finding.code_snippet[:200].replace(chr(10), chr(10) + '    ')}")
    else:
        output.append("\n✅ No security issues found!")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description="AI Agent Security Scanner - Detect vulnerabilities in agent implementations"
    )
    parser.add_argument("path", help="Path to project directory to scan")
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--output", "-o",
        help="Write results to file"
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Minimum severity to report"
    )

    args = parser.parse_args()

    project_path = Path(args.path)
    if not project_path.exists():
        print(f"Error: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {project_path} for agent security vulnerabilities...", file=sys.stderr)
    result = scan_directory(project_path)

    # Filter by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_level = severity_order.get(args.min_severity, 3)
    result.findings = [
        f for f in result.findings
        if severity_order.get(f.severity, 4) <= min_level
    ]

    if args.json or args.output:
        output = {
            "project_path": result.project_path,
            "scan_time": result.scan_time,
            "total_files_scanned": result.total_files_scanned,
            "frameworks_detected": result.frameworks_detected,
            "agents_found": result.agents_found,
            "tools_found": result.tools_found,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "owasp_id": f.owasp_id,
                    "code_snippet": f.code_snippet,
                }
                for f in result.findings
            ],
        }

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(output, indent=2))
    else:
        print(format_console_output(result))

    # Exit code based on findings
    critical_or_high = any(
        f.severity in ("CRITICAL", "HIGH")
        for f in result.findings
    )
    sys.exit(1 if critical_or_high else 0)


if __name__ == "__main__":
    main()
