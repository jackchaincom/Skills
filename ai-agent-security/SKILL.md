---
name: ai-agent-security
description: Audits AI agent systems for security vulnerabilities including excessive agency, tool abuse, prompt injection in agent contexts, unsafe inter-agent communication, and missing sandboxing. Covers LangChain, LlamaIndex, AutoGPT, CrewAI, and custom agent implementations.
---

# AI Agent Security Audit

This skill audits AI agent systems for security vulnerabilities based on OWASP LLM Top 10:2025, focusing on agent-specific risks.

## When to Use

- Reviewing LangChain/LlamaIndex agent implementations
- Auditing multi-agent systems (CrewAI, AutoGPT, custom)
- Assessing tool/function calling security
- Checking agent permission boundaries
- Evaluating agent sandboxing and isolation

## Quick Start

```bash
# Run agent security scan
python .claude/skills/ai-agent-security/scripts/agent-scanner.py /path/to/project

# JSON output for CI/CD
python .claude/skills/ai-agent-security/scripts/agent-scanner.py /path/to/project --json
```

---

## Agent Security Threat Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI Agent Attack Surface                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     │
│  │ User Input   │────▶│   Agent      │────▶│   Tools      │     │
│  │ (Untrusted)  │     │   (LLM)      │     │ (Actions)    │     │
│  └──────────────┘     └──────┬───────┘     └──────────────┘     │
│         │                    │                    │               │
│         ▼                    ▼                    ▼               │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    ATTACK VECTORS                        │    │
│  ├─────────────────────────────────────────────────────────┤    │
│  │ • Prompt Injection → Agent executes malicious commands  │    │
│  │ • Tool Abuse → Agent misuses legitimate tools           │    │
│  │ • Excessive Agency → Agent has too many permissions     │    │
│  │ • Agent Loops → Resource exhaustion / DoS               │    │
│  │ • Data Exfiltration → Agent leaks sensitive data        │    │
│  │ • Privilege Escalation → Agent gains higher access      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Audit Workflow

### Step 1: Identify Agent Components

Scan for agent frameworks and patterns:

```python
# LangChain Agents
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.agents import initialize_agent, AgentType

# LlamaIndex Agents
from llama_index.agent import OpenAIAgent, ReActAgent

# CrewAI
from crewai import Agent, Task, Crew

# AutoGPT patterns
class AutoGPTAgent:
    def run(self, goals: list):
        ...
```

### Step 2: Audit Tool Definitions

Check tool security:

| Risk | Pattern | Severity |
|------|---------|----------|
| Shell execution | `subprocess`, `os.system` in tools | CRITICAL |
| File system access | `open()`, `pathlib` without restrictions | HIGH |
| Network requests | `requests`, `urllib` to arbitrary URLs | HIGH |
| Database queries | Raw SQL in tools | HIGH |
| Code execution | `exec()`, `eval()` in tools | CRITICAL |

Reference: [Tool Permission Model](references/tool-permissions.md)

### Step 3: Check Permission Boundaries

Verify least-privilege principle:

```python
# ❌ UNSAFE - Tool can access anything
@tool
def read_file(path: str) -> str:
    return open(path).read()

# ✅ SAFE - Restricted to allowed paths
@tool
def read_file(path: str) -> str:
    allowed_paths = ["/data/public/", "/tmp/agent/"]
    if not any(path.startswith(p) for p in allowed_paths):
        raise PermissionError(f"Access denied: {path}")
    return open(path).read()
```

Reference: [Agent Security Patterns](references/agent-patterns.md)

### Step 4: Evaluate Agent Loops

Check for runaway agent protection:

```python
# ❌ UNSAFE - No iteration limit
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
)

# ✅ SAFE - With limits
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    max_iterations=10,           # Limit iterations
    max_execution_time=60,       # Timeout in seconds
    early_stopping_method="force",
)
```

### Step 5: Audit Inter-Agent Communication

For multi-agent systems:

| Risk | Check |
|------|-------|
| Message injection | Are agent messages validated? |
| Trust boundaries | Do agents verify sender identity? |
| Data leakage | Is sensitive data shared between agents? |
| Escalation | Can one agent grant permissions to another? |

Reference: [Sandboxing Guide](references/sandboxing.md)

### Step 6: Generate Report

Use template: [assets/agent-audit-template.md](assets/agent-audit-template.md)

---

## OWASP LLM Top 10 Coverage (Agent Focus)

| ID | Vulnerability | Agent-Specific Risk |
|----|---------------|---------------------|
| LLM01 | Prompt Injection | Agent executes injected commands |
| LLM02 | Sensitive Information Disclosure | Agent leaks data via tools |
| LLM03 | Supply Chain | Malicious tool packages |
| LLM04 | Data and Model Poisoning | Poisoned agent memory |
| LLM05 | Improper Output Handling | Tool output not sanitized |
| **LLM06** | **Excessive Agency** | **Too many permissions** |
| LLM07 | System Prompt Leakage | Agent prompt exposed |
| LLM08 | Vector and Embedding Weaknesses | RAG retrieval manipulation |
| LLM09 | Misinformation | Agent spreads false info |
| LLM10 | Unbounded Consumption | Agent loops, resource exhaustion |

---

## Critical Patterns to Detect

### 1. Unrestricted Tool Access

```python
# CRITICAL: Tool can execute any shell command
@tool
def run_command(command: str) -> str:
    """Run a shell command."""
    return subprocess.check_output(command, shell=True).decode()
```

### 2. No Input Validation

```python
# CRITICAL: SQL injection via agent
@tool
def query_database(query: str) -> str:
    """Execute SQL query."""
    return db.execute(query)  # No parameterization!
```

### 3. Excessive Permissions

```python
# HIGH: Agent has admin-level tools
tools = [
    delete_user_tool,      # Can delete any user
    modify_settings_tool,  # Can change system settings
    execute_code_tool,     # Can run arbitrary code
]
```

### 4. Missing Rate Limits

```python
# HIGH: No rate limiting on expensive operations
@tool
def call_external_api(endpoint: str) -> str:
    """Call any external API."""
    return requests.get(endpoint).text  # No rate limit!
```

### 5. Unprotected Agent Memory

```python
# MEDIUM: Memory can be poisoned
agent = ConversationalAgent(
    memory=ConversationBufferMemory(),  # No validation
    tools=tools,
)
```

---

## Remediation Quick Reference

| Issue | Fix |
|-------|-----|
| Shell execution in tools | Remove or sandbox with restricted shell |
| Unrestricted file access | Implement path allowlist |
| No iteration limits | Add `max_iterations` and `max_execution_time` |
| SQL injection | Use parameterized queries |
| Missing authentication | Verify user identity before tool execution |
| No rate limiting | Implement per-user/per-tool rate limits |
| Excessive tool permissions | Apply principle of least privilege |
| Unvalidated agent output | Sanitize before displaying or executing |

---

## Framework-Specific Checks

### LangChain

```python
# Check AgentExecutor configuration
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=False,           # ✓ Don't log sensitive data
    max_iterations=10,       # ✓ Limit iterations
    max_execution_time=60,   # ✓ Timeout
    handle_parsing_errors=True,  # ✓ Handle errors gracefully
)
```

### LlamaIndex

```python
# Check ReActAgent configuration
agent = ReActAgent.from_tools(
    tools,
    llm=llm,
    verbose=False,
    max_iterations=10,
)
```

### CrewAI

```python
# Check Agent permissions
agent = Agent(
    role="Researcher",
    goal="Find information",
    backstory="...",
    allow_delegation=False,  # ✓ Disable if not needed
    verbose=False,
)
```

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: AI Agent Security Scan
  run: |
    python .claude/skills/ai-agent-security/scripts/agent-scanner.py . --json > agent-security.json

- name: Check for Critical Issues
  run: |
    if grep -q '"severity": "CRITICAL"' agent-security.json; then
      echo "Critical agent security issues found!"
      exit 1
    fi
```

---

## References

- [Agent Security Patterns](references/agent-patterns.md)
- [Tool Permission Model](references/tool-permissions.md)
- [Sandboxing Guide](references/sandboxing.md)
- [OWASP LLM06 - Excessive Agency](https://genai.owasp.org/)
