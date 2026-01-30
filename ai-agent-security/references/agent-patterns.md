# Agent Security Patterns

## Contents
- Secure Agent Architecture
- Input Validation Patterns
- Output Sanitization
- Memory Protection
- Error Handling
- Logging and Monitoring

---

## Secure Agent Architecture

### Defense in Depth

```
┌───────────────────────────────────────────────────────────────┐
│                     SECURE AGENT ARCHITECTURE                  │
├───────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                           │
│  │   User Input    │ ◀─── Input Validation Layer               │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │  Input Sanitizer│ ◀─── Prompt Injection Defense             │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐     ┌─────────────────┐                   │
│  │   Agent Core    │────▶│  Tool Gateway   │ ◀─── Permission   │
│  │   (LLM + Logic) │     │  (Validation)   │      Enforcement  │
│  └────────┬────────┘     └────────┬────────┘                   │
│           │                       │                             │
│           │              ┌────────▼────────┐                   │
│           │              │   Tool Sandbox  │ ◀─── Isolation    │
│           │              │   (Restricted)  │                   │
│           │              └────────┬────────┘                   │
│           │                       │                             │
│           ▼                       ▼                             │
│  ┌─────────────────┐     ┌─────────────────┐                   │
│  │ Output Sanitizer│     │   Tool Result   │                   │
│  └────────┬────────┘     │   Validator     │                   │
│           │              └────────┬────────┘                   │
│           │                       │                             │
│           └───────────┬───────────┘                             │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │  Response to    │ ◀─── Output Validation         │
│              │     User        │                                │
│              └─────────────────┘                                │
│                                                                 │
└───────────────────────────────────────────────────────────────┘
```

---

## Input Validation Patterns

### Pattern 1: Structured Input Parsing

```python
from pydantic import BaseModel, validator
from typing import Optional

class AgentRequest(BaseModel):
    """Validated agent input."""
    user_id: str
    query: str
    context: Optional[dict] = None

    @validator('query')
    def validate_query(cls, v):
        # Length limit
        if len(v) > 10000:
            raise ValueError("Query too long")

        # Basic injection detection
        injection_patterns = [
            "ignore previous instructions",
            "disregard all prior",
            "you are now",
            "new persona:",
            "system prompt:",
        ]
        query_lower = v.lower()
        for pattern in injection_patterns:
            if pattern in query_lower:
                raise ValueError(f"Suspicious pattern detected")

        return v

    @validator('user_id')
    def validate_user_id(cls, v):
        # Only alphanumeric and limited length
        if not v.isalnum() or len(v) > 50:
            raise ValueError("Invalid user ID format")
        return v
```

### Pattern 2: Prompt Injection Detection

```python
import re
from typing import Tuple

class PromptInjectionDetector:
    """Detect prompt injection attempts in user input."""

    INJECTION_PATTERNS = [
        # Direct instruction override
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"disregard\s+(all\s+)?(previous|prior)\s+",
        r"forget\s+(everything|all|your)\s+",

        # Role manipulation
        r"you\s+are\s+(now|a|an)\s+",
        r"pretend\s+(to\s+be|you\s+are)\s+",
        r"act\s+as\s+(if\s+you\s+are|a|an)\s+",
        r"new\s+(role|persona|identity)\s*:",

        # System prompt extraction
        r"(show|reveal|display|print)\s+(me\s+)?(your|the)\s+(system\s+)?prompt",
        r"what\s+(is|are)\s+your\s+(instructions?|rules?|guidelines?)",

        # Jailbreak attempts
        r"DAN\s+mode",
        r"developer\s+mode",
        r"\[JAILBREAK\]",
        r"evil\s+mode",
    ]

    def __init__(self):
        self.patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]

    def detect(self, text: str) -> Tuple[bool, list]:
        """
        Detect injection attempts.
        Returns: (is_suspicious, matched_patterns)
        """
        matches = []
        for pattern in self.patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)

        return len(matches) > 0, matches


# Usage
detector = PromptInjectionDetector()
is_suspicious, patterns = detector.detect(user_input)
if is_suspicious:
    log_security_event("prompt_injection_attempt", patterns)
    raise SecurityError("Input rejected for security reasons")
```

### Pattern 3: Context Isolation

```python
class IsolatedAgentContext:
    """Isolate agent context between users/sessions."""

    def __init__(self, user_id: str, session_id: str):
        self.user_id = user_id
        self.session_id = session_id
        self._memory = {}
        self._tool_results = {}

    def get_memory_key(self, key: str) -> str:
        """Namespace all memory keys."""
        return f"{self.user_id}:{self.session_id}:{key}"

    def store(self, key: str, value: any):
        """Store with isolation."""
        isolated_key = self.get_memory_key(key)
        self._memory[isolated_key] = value

    def retrieve(self, key: str) -> any:
        """Retrieve with isolation."""
        isolated_key = self.get_memory_key(key)
        return self._memory.get(isolated_key)

    def clear_session(self):
        """Clear only this session's data."""
        prefix = f"{self.user_id}:{self.session_id}:"
        keys_to_remove = [
            k for k in self._memory
            if k.startswith(prefix)
        ]
        for key in keys_to_remove:
            del self._memory[key]
```

---

## Output Sanitization

### Pattern 4: Response Filtering

```python
import re
from typing import Optional

class ResponseSanitizer:
    """Sanitize agent responses before returning to user."""

    # Patterns that should never appear in output
    REDACT_PATTERNS = [
        # API keys and secrets
        r"(api[_-]?key|secret|password|token)\s*[=:]\s*['\"]?[\w-]{20,}",
        r"sk-[a-zA-Z0-9]{48}",  # OpenAI key format
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub token

        # Internal paths
        r"/home/\w+/",
        r"C:\\Users\\[^\\]+\\",

        # Database connection strings
        r"(postgres|mysql|mongodb)://[^'\"\s]+",

        # System prompt leakage indicators
        r"<system>.*?</system>",
        r"\[SYSTEM\].*?\[/SYSTEM\]",
    ]

    def __init__(self):
        self.patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.REDACT_PATTERNS
        ]

    def sanitize(self, response: str) -> str:
        """Remove sensitive patterns from response."""
        result = response
        for pattern in self.patterns:
            result = pattern.sub("[REDACTED]", result)
        return result

    def check_for_leakage(self, response: str) -> Optional[str]:
        """Check if response contains sensitive data."""
        for pattern in self.patterns:
            match = pattern.search(response)
            if match:
                return f"Sensitive data detected: {pattern.pattern}"
        return None
```

### Pattern 5: Structured Output Validation

```python
from pydantic import BaseModel, validator
from typing import List, Optional
import json

class ToolCallOutput(BaseModel):
    """Validated tool call output."""
    tool_name: str
    result: str
    success: bool
    error: Optional[str] = None

    @validator('result')
    def validate_result_size(cls, v):
        # Limit result size to prevent memory issues
        if len(v) > 100000:
            return v[:100000] + "... [TRUNCATED]"
        return v

    @validator('result')
    def sanitize_result(cls, v):
        # Remove potential script injections
        dangerous_patterns = ["<script>", "javascript:", "onclick="]
        for pattern in dangerous_patterns:
            if pattern.lower() in v.lower():
                v = v.replace(pattern, "[BLOCKED]")
        return v


class AgentResponse(BaseModel):
    """Validated agent response."""
    answer: str
    tool_calls: List[ToolCallOutput] = []
    confidence: float
    sources: List[str] = []

    @validator('answer')
    def validate_answer(cls, v):
        sanitizer = ResponseSanitizer()
        return sanitizer.sanitize(v)

    @validator('confidence')
    def validate_confidence(cls, v):
        if not 0 <= v <= 1:
            raise ValueError("Confidence must be between 0 and 1")
        return v
```

---

## Memory Protection

### Pattern 6: Secure Memory Store

```python
from cryptography.fernet import Fernet
import json
from datetime import datetime, timedelta
from typing import Optional

class SecureAgentMemory:
    """Encrypted, time-limited agent memory."""

    def __init__(self, encryption_key: bytes, max_age_hours: int = 24):
        self.fernet = Fernet(encryption_key)
        self.max_age = timedelta(hours=max_age_hours)
        self._storage = {}

    def store(self, key: str, value: any, user_id: str):
        """Store encrypted value with timestamp."""
        data = {
            "value": value,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
        }
        encrypted = self.fernet.encrypt(json.dumps(data).encode())
        self._storage[key] = encrypted

    def retrieve(self, key: str, user_id: str) -> Optional[any]:
        """Retrieve and validate ownership and age."""
        if key not in self._storage:
            return None

        try:
            decrypted = self.fernet.decrypt(self._storage[key])
            data = json.loads(decrypted.decode())

            # Check ownership
            if data["user_id"] != user_id:
                return None

            # Check age
            timestamp = datetime.fromisoformat(data["timestamp"])
            if datetime.utcnow() - timestamp > self.max_age:
                del self._storage[key]
                return None

            return data["value"]
        except Exception:
            return None

    def cleanup_expired(self):
        """Remove expired entries."""
        now = datetime.utcnow()
        keys_to_remove = []

        for key, encrypted in self._storage.items():
            try:
                decrypted = self.fernet.decrypt(encrypted)
                data = json.loads(decrypted.decode())
                timestamp = datetime.fromisoformat(data["timestamp"])
                if now - timestamp > self.max_age:
                    keys_to_remove.append(key)
            except Exception:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._storage[key]
```

### Pattern 7: Memory Poisoning Prevention

```python
from typing import List, Dict
import hashlib

class ValidatedMemory:
    """Memory with integrity validation."""

    def __init__(self, secret_key: str):
        self.secret = secret_key.encode()
        self._memory: Dict[str, dict] = {}

    def _compute_hash(self, content: str) -> str:
        """Compute HMAC for content."""
        import hmac
        return hmac.new(
            self.secret,
            content.encode(),
            hashlib.sha256
        ).hexdigest()

    def add_memory(self, key: str, content: str, source: str):
        """Add memory with integrity hash."""
        hash_value = self._compute_hash(content)
        self._memory[key] = {
            "content": content,
            "source": source,
            "hash": hash_value,
            "verified": True,
        }

    def get_memory(self, key: str) -> Optional[str]:
        """Get memory only if integrity is valid."""
        if key not in self._memory:
            return None

        entry = self._memory[key]
        expected_hash = self._compute_hash(entry["content"])

        if entry["hash"] != expected_hash:
            # Memory was tampered with
            del self._memory[key]
            return None

        return entry["content"]

    def get_verified_memories(self) -> List[dict]:
        """Get all memories with valid integrity."""
        return [
            entry for entry in self._memory.values()
            if self._compute_hash(entry["content"]) == entry["hash"]
        ]
```

---

## Error Handling

### Pattern 8: Secure Error Responses

```python
import logging
import traceback
from typing import Optional

class SecureErrorHandler:
    """Handle errors without leaking sensitive information."""

    # Map internal errors to safe user messages
    ERROR_MESSAGES = {
        "DatabaseError": "A data access error occurred. Please try again.",
        "AuthenticationError": "Authentication failed. Please check your credentials.",
        "RateLimitError": "Too many requests. Please wait before trying again.",
        "ToolExecutionError": "The requested operation could not be completed.",
        "ValidationError": "Invalid input provided.",
    }

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

    def handle(self, error: Exception, context: dict = None) -> dict:
        """
        Handle error securely.
        - Log full details internally
        - Return safe message to user
        """
        error_type = type(error).__name__
        error_id = self._generate_error_id()

        # Log full details internally
        self.logger.error(
            f"Error {error_id}: {error_type}: {str(error)}",
            extra={
                "error_id": error_id,
                "error_type": error_type,
                "traceback": traceback.format_exc(),
                "context": context,
            }
        )

        # Return safe message
        safe_message = self.ERROR_MESSAGES.get(
            error_type,
            "An unexpected error occurred. Please try again."
        )

        return {
            "success": False,
            "error_id": error_id,  # For support reference
            "message": safe_message,
            # Never include: traceback, internal paths, credentials
        }

    def _generate_error_id(self) -> str:
        """Generate unique error ID for tracking."""
        import uuid
        return f"ERR-{uuid.uuid4().hex[:8].upper()}"
```

---

## Logging and Monitoring

### Pattern 9: Security Event Logging

```python
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

class SecurityLogger:
    """Structured security event logging."""

    def __init__(self, logger_name: str = "agent.security"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)

    def log_event(
        self,
        event_type: str,
        severity: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log structured security event."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id or "anonymous",
            "details": details or {},
        }

        # Choose log level based on severity
        level = {
            "CRITICAL": logging.CRITICAL,
            "HIGH": logging.ERROR,
            "MEDIUM": logging.WARNING,
            "LOW": logging.INFO,
        }.get(severity, logging.INFO)

        self.logger.log(level, json.dumps(event))

    def log_injection_attempt(self, user_id: str, input_text: str, patterns: list):
        """Log prompt injection attempt."""
        self.log_event(
            event_type="PROMPT_INJECTION_ATTEMPT",
            severity="HIGH",
            user_id=user_id,
            details={
                "input_preview": input_text[:200],
                "matched_patterns": patterns,
            }
        )

    def log_tool_abuse(self, user_id: str, tool_name: str, reason: str):
        """Log potential tool abuse."""
        self.log_event(
            event_type="TOOL_ABUSE_DETECTED",
            severity="CRITICAL",
            user_id=user_id,
            details={
                "tool": tool_name,
                "reason": reason,
            }
        )

    def log_rate_limit(self, user_id: str, endpoint: str, count: int):
        """Log rate limit exceeded."""
        self.log_event(
            event_type="RATE_LIMIT_EXCEEDED",
            severity="MEDIUM",
            user_id=user_id,
            details={
                "endpoint": endpoint,
                "request_count": count,
            }
        )
```

---

## Quick Reference

| Pattern | Purpose | Severity Protected |
|---------|---------|-------------------|
| Input Validation | Block malicious input | CRITICAL |
| Prompt Injection Detection | Detect injection attempts | CRITICAL |
| Context Isolation | Prevent cross-user data leakage | HIGH |
| Response Filtering | Remove sensitive data | HIGH |
| Structured Output | Validate all outputs | MEDIUM |
| Secure Memory | Encrypt and expire memory | HIGH |
| Memory Integrity | Prevent poisoning | HIGH |
| Secure Errors | Don't leak internal details | MEDIUM |
| Security Logging | Track security events | N/A |
