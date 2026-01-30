# Agent Sandboxing Guide

## Contents
- Sandboxing Strategies
- Docker Isolation
- Process Isolation
- Network Isolation
- Resource Limits
- Multi-Agent Security

---

## Sandboxing Strategies

### Defense in Depth Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                    AGENT SANDBOXING LAYERS                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Layer 1: Application Level                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ • Input validation                                        │    │
│  │ • Permission checks                                       │    │
│  │ • Rate limiting                                           │    │
│  │ • Output sanitization                                     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              ▼                                    │
│  Layer 2: Language Level                                         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ • RestrictedPython                                        │    │
│  │ • AST filtering                                           │    │
│  │ • Builtin restrictions                                    │    │
│  │ • Import controls                                         │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              ▼                                    │
│  Layer 3: Process Level                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ • Separate process                                        │    │
│  │ • Resource limits (ulimit)                                │    │
│  │ • seccomp filters                                         │    │
│  │ • Capabilities dropping                                   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              ▼                                    │
│  Layer 4: Container Level                                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ • Docker/Podman containers                                │    │
│  │ • Network isolation                                       │    │
│  │ • Filesystem isolation                                    │    │
│  │ • Resource quotas                                         │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              ▼                                    │
│  Layer 5: Infrastructure Level                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ • VMs / Firecracker                                       │    │
│  │ • Network segmentation                                    │    │
│  │ • Storage encryption                                      │    │
│  │ • Audit logging                                           │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Choosing Sandboxing Level

| Use Case | Recommended Level | Rationale |
|----------|------------------|-----------|
| Simple calculations | Language (RestrictedPython) | Fast, low overhead |
| File operations | Process + Path restrictions | Isolate filesystem access |
| Network requests | Container + Network policies | Control egress |
| Code execution | Container (Docker) | Full isolation |
| Untrusted code | VM (Firecracker) | Maximum isolation |
| Multi-tenant | Container + Kubernetes | Per-tenant isolation |

---

## Docker Isolation

### Secure Container Configuration

```python
import docker
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class SandboxConfig:
    """Configuration for Docker sandbox."""
    image: str = "python:3.11-slim"
    memory_limit: str = "256m"
    memory_swap: str = "256m"  # Same as memory = no swap
    cpu_period: int = 100000
    cpu_quota: int = 50000  # 50% of one CPU
    pids_limit: int = 50  # Max processes
    timeout: int = 30  # seconds
    network_disabled: bool = True
    read_only: bool = True
    user: str = "nobody"  # Non-root user
    cap_drop: List[str] = None  # Drop all capabilities
    security_opt: List[str] = None  # Security options

    def __post_init__(self):
        if self.cap_drop is None:
            self.cap_drop = ["ALL"]
        if self.security_opt is None:
            self.security_opt = [
                "no-new-privileges:true",
                "seccomp=unconfined",  # Or custom profile
            ]


class SecureDockerSandbox:
    """Secure Docker sandbox for agent code execution."""

    def __init__(self, config: SandboxConfig = None):
        self.config = config or SandboxConfig()
        self.client = docker.from_env()

    def execute(
        self,
        code: str,
        allowed_imports: List[str] = None,
    ) -> Dict[str, any]:
        """Execute code in secure container."""
        import tempfile
        import os

        # Prepare code with import restrictions
        wrapped_code = self._wrap_code(code, allowed_imports or [])

        # Write to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False
        ) as f:
            f.write(wrapped_code)
            code_path = f.name

        try:
            result = self.client.containers.run(
                self.config.image,
                command=f"python /sandbox/code.py",
                volumes={
                    code_path: {"bind": "/sandbox/code.py", "mode": "ro"}
                },
                mem_limit=self.config.memory_limit,
                memswap_limit=self.config.memory_swap,
                cpu_period=self.config.cpu_period,
                cpu_quota=self.config.cpu_quota,
                pids_limit=self.config.pids_limit,
                network_disabled=self.config.network_disabled,
                read_only=self.config.read_only,
                user=self.config.user,
                cap_drop=self.config.cap_drop,
                security_opt=self.config.security_opt,
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
            )

            return {
                "success": True,
                "output": result.decode() if result else "",
                "error": None,
            }

        except docker.errors.ContainerError as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": f"Sandbox error: {str(e)}",
            }
        finally:
            os.unlink(code_path)

    def _wrap_code(self, code: str, allowed_imports: List[str]) -> str:
        """Wrap code with import restrictions."""
        # Generate import whitelist
        import_check = ""
        if allowed_imports:
            import_check = f"""
import sys
ALLOWED_IMPORTS = {set(allowed_imports)}

class ImportRestrictor:
    def find_module(self, name, path=None):
        if name.split('.')[0] not in ALLOWED_IMPORTS:
            raise ImportError(f"Import not allowed: {{name}}")
        return None

sys.meta_path.insert(0, ImportRestrictor())
"""

        return import_check + code
```

### Docker Compose for Agent Sandbox

```yaml
# docker-compose.sandbox.yml
version: '3.8'

services:
  agent-sandbox:
    image: python:3.11-slim
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    networks:
      - sandbox-network
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
          pids: 50
        reservations:
          cpus: '0.1'
          memory: 64M
    tmpfs:
      - /tmp:size=10M,mode=1777
    volumes:
      - type: bind
        source: ./sandbox-code
        target: /code
        read_only: true

networks:
  sandbox-network:
    driver: bridge
    internal: true  # No external access
```

---

## Process Isolation

### Pattern 1: Subprocess with Resource Limits

```python
import subprocess
import resource
import os
import signal
from typing import Tuple, Optional

class ProcessSandbox:
    """Execute code in isolated subprocess with resource limits."""

    def __init__(
        self,
        max_memory_mb: int = 256,
        max_cpu_seconds: int = 10,
        max_file_size_mb: int = 10,
        max_processes: int = 10,
    ):
        self.max_memory = max_memory_mb * 1024 * 1024
        self.max_cpu = max_cpu_seconds
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.max_processes = max_processes

    def _set_limits(self):
        """Set resource limits for child process."""
        # Memory limit
        resource.setrlimit(
            resource.RLIMIT_AS,
            (self.max_memory, self.max_memory)
        )

        # CPU time limit
        resource.setrlimit(
            resource.RLIMIT_CPU,
            (self.max_cpu, self.max_cpu)
        )

        # File size limit
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (self.max_file_size, self.max_file_size)
        )

        # Process limit
        resource.setrlimit(
            resource.RLIMIT_NPROC,
            (self.max_processes, self.max_processes)
        )

        # Disable core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def execute(
        self,
        code: str,
        timeout: int = 30,
    ) -> Tuple[str, str, int]:
        """
        Execute Python code in sandboxed subprocess.
        Returns: (stdout, stderr, return_code)
        """
        import tempfile

        # Write code to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False
        ) as f:
            f.write(code)
            code_path = f.name

        try:
            process = subprocess.Popen(
                ["python", code_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self._set_limits,
                start_new_session=True,  # New process group
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return (
                    stdout.decode(),
                    stderr.decode(),
                    process.returncode,
                )
            except subprocess.TimeoutExpired:
                # Kill entire process group
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                return "", "Execution timed out", -1

        finally:
            os.unlink(code_path)
```

### Pattern 2: seccomp Profile

```python
import ctypes
import prctl

# Seccomp filter for Python sandbox
ALLOWED_SYSCALLS = [
    # Basic operations
    "read", "write", "close", "fstat",
    # Memory management
    "mmap", "munmap", "mprotect", "brk",
    # Process management (limited)
    "exit", "exit_group",
    # File operations (read-only)
    "openat", "newfstatat", "lseek",
    # Signals
    "rt_sigaction", "rt_sigprocmask",
    # Time
    "clock_gettime", "gettimeofday",
]

def apply_seccomp_filter():
    """Apply seccomp filter to restrict syscalls."""
    try:
        import seccomp

        # Default deny
        f = seccomp.SyscallFilter(defaction=seccomp.KILL)

        # Allow specific syscalls
        for syscall in ALLOWED_SYSCALLS:
            f.add_rule(seccomp.ALLOW, syscall)

        f.load()
        return True
    except Exception as e:
        print(f"Failed to apply seccomp: {e}")
        return False
```

---

## Network Isolation

### Pattern 3: Network Namespace Isolation

```python
import subprocess
from typing import List, Optional

class NetworkIsolator:
    """Isolate agent network access using network namespaces."""

    def __init__(self, allowed_hosts: List[str] = None):
        self.allowed_hosts = allowed_hosts or []

    def create_isolated_namespace(self, name: str) -> bool:
        """Create isolated network namespace."""
        try:
            # Create namespace
            subprocess.run(
                ["ip", "netns", "add", name],
                check=True, capture_output=True
            )

            # Add loopback
            subprocess.run(
                ["ip", "netns", "exec", name,
                 "ip", "link", "set", "lo", "up"],
                check=True, capture_output=True
            )

            return True
        except subprocess.CalledProcessError:
            return False

    def execute_in_namespace(
        self,
        namespace: str,
        command: List[str],
    ) -> subprocess.CompletedProcess:
        """Execute command in network namespace."""
        return subprocess.run(
            ["ip", "netns", "exec", namespace] + command,
            capture_output=True, text=True
        )

    def cleanup_namespace(self, name: str) -> bool:
        """Remove network namespace."""
        try:
            subprocess.run(
                ["ip", "netns", "delete", name],
                check=True, capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False


# Alternative: iptables-based isolation
class IPTablesIsolator:
    """Isolate network using iptables rules."""

    def __init__(self, chain_name: str = "AGENT_SANDBOX"):
        self.chain = chain_name

    def setup_chain(self):
        """Create iptables chain for agent isolation."""
        commands = [
            # Create chain
            f"iptables -N {self.chain}",
            # Default drop
            f"iptables -A {self.chain} -j DROP",
        ]
        for cmd in commands:
            subprocess.run(cmd.split(), capture_output=True)

    def allow_host(self, host: str, port: int = 443):
        """Allow traffic to specific host."""
        subprocess.run([
            "iptables", "-I", self.chain, "1",
            "-d", host, "-p", "tcp", "--dport", str(port),
            "-j", "ACCEPT"
        ], capture_output=True)

    def apply_to_user(self, uid: int):
        """Apply chain to specific user."""
        subprocess.run([
            "iptables", "-A", "OUTPUT",
            "-m", "owner", "--uid-owner", str(uid),
            "-j", self.chain
        ], capture_output=True)
```

### Pattern 4: Proxy-based Network Control

```python
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.proxy import ProxyConfig, ProxyServer
from mitmproxy.controller import handler
from typing import Set

class AgentNetworkProxy:
    """Proxy to control agent network access."""

    def __init__(self, allowed_domains: Set[str]):
        self.allowed_domains = allowed_domains
        self.blocked_requests = []

    def request(self, flow: http.HTTPFlow):
        """Handle outgoing requests."""
        host = flow.request.host

        # Check if domain is allowed
        if not self._is_allowed(host):
            flow.kill()
            self.blocked_requests.append({
                "host": host,
                "path": flow.request.path,
                "reason": "Domain not in allowlist",
            })
            return

        # Log allowed request
        print(f"Allowed: {flow.request.method} {flow.request.url}")

    def _is_allowed(self, host: str) -> bool:
        """Check if host is in allowlist."""
        # Exact match
        if host in self.allowed_domains:
            return True

        # Subdomain match
        for allowed in self.allowed_domains:
            if host.endswith(f".{allowed}"):
                return True

        return False


# Usage: Set HTTP_PROXY and HTTPS_PROXY for agent process
# Then all network requests go through the proxy
```

---

## Resource Limits

### Pattern 5: Comprehensive Resource Limiter

```python
import resource
import signal
import threading
from typing import Callable, Any
from dataclasses import dataclass

@dataclass
class ResourceLimits:
    """Resource limits configuration."""
    max_memory_mb: int = 256
    max_cpu_seconds: int = 30
    max_file_size_mb: int = 10
    max_open_files: int = 100
    max_processes: int = 10
    max_execution_time: int = 60


class ResourceLimiter:
    """Apply and monitor resource limits."""

    def __init__(self, limits: ResourceLimits = None):
        self.limits = limits or ResourceLimits()

    def apply_limits(self):
        """Apply resource limits to current process."""
        # Memory
        mem_bytes = self.limits.max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))

        # CPU time
        resource.setrlimit(
            resource.RLIMIT_CPU,
            (self.limits.max_cpu_seconds, self.limits.max_cpu_seconds)
        )

        # File size
        file_bytes = self.limits.max_file_size_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))

        # Open files
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (self.limits.max_open_files, self.limits.max_open_files)
        )

        # Processes
        resource.setrlimit(
            resource.RLIMIT_NPROC,
            (self.limits.max_processes, self.limits.max_processes)
        )

        # No core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def execute_with_limits(
        self,
        func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """Execute function with resource limits and timeout."""
        result = [None]
        error = [None]

        def wrapper():
            try:
                self.apply_limits()
                result[0] = func(*args, **kwargs)
            except Exception as e:
                error[0] = e

        # Run in thread with timeout
        thread = threading.Thread(target=wrapper)
        thread.start()
        thread.join(timeout=self.limits.max_execution_time)

        if thread.is_alive():
            raise TimeoutError("Execution time limit exceeded")

        if error[0]:
            raise error[0]

        return result[0]
```

---

## Multi-Agent Security

### Pattern 6: Secure Inter-Agent Communication

```python
import hashlib
import hmac
import json
import time
from typing import Dict, Optional
from dataclasses import dataclass, asdict

@dataclass
class AgentMessage:
    """Signed message between agents."""
    sender_id: str
    recipient_id: str
    content: str
    timestamp: float
    nonce: str
    signature: str = ""


class SecureAgentCommunication:
    """Secure communication between agents."""

    def __init__(self, agent_id: str, secret_key: str):
        self.agent_id = agent_id
        self.secret = secret_key.encode()
        self._nonce_cache: Dict[str, float] = {}
        self._nonce_expiry = 300  # 5 minutes

    def create_message(
        self,
        recipient_id: str,
        content: str
    ) -> AgentMessage:
        """Create signed message."""
        import uuid

        msg = AgentMessage(
            sender_id=self.agent_id,
            recipient_id=recipient_id,
            content=content,
            timestamp=time.time(),
            nonce=str(uuid.uuid4()),
        )

        # Sign message
        msg.signature = self._sign(msg)
        return msg

    def verify_message(self, msg: AgentMessage) -> bool:
        """Verify message signature and freshness."""
        # Check recipient
        if msg.recipient_id != self.agent_id:
            return False

        # Check timestamp (within 5 minutes)
        age = time.time() - msg.timestamp
        if age > self._nonce_expiry or age < -60:
            return False

        # Check nonce (prevent replay)
        if msg.nonce in self._nonce_cache:
            return False

        # Verify signature
        expected_sig = self._sign(msg)
        if not hmac.compare_digest(msg.signature, expected_sig):
            return False

        # Cache nonce
        self._nonce_cache[msg.nonce] = time.time()
        self._cleanup_nonces()

        return True

    def _sign(self, msg: AgentMessage) -> str:
        """Create HMAC signature."""
        data = f"{msg.sender_id}:{msg.recipient_id}:{msg.content}:{msg.timestamp}:{msg.nonce}"
        return hmac.new(
            self.secret,
            data.encode(),
            hashlib.sha256
        ).hexdigest()

    def _cleanup_nonces(self):
        """Remove expired nonces."""
        now = time.time()
        expired = [
            nonce for nonce, ts in self._nonce_cache.items()
            if now - ts > self._nonce_expiry
        ]
        for nonce in expired:
            del self._nonce_cache[nonce]
```

### Pattern 7: Agent Trust Levels

```python
from enum import IntEnum
from typing import Set, Dict

class TrustLevel(IntEnum):
    """Trust levels for agents."""
    UNTRUSTED = 0
    SANDBOXED = 1
    LIMITED = 2
    STANDARD = 3
    ELEVATED = 4
    ADMIN = 5


class AgentTrustManager:
    """Manage trust levels between agents."""

    def __init__(self):
        self._trust_levels: Dict[str, TrustLevel] = {}
        self._allowed_communications: Dict[TrustLevel, Set[TrustLevel]] = {
            TrustLevel.UNTRUSTED: set(),  # Can't communicate
            TrustLevel.SANDBOXED: {TrustLevel.SANDBOXED},
            TrustLevel.LIMITED: {TrustLevel.SANDBOXED, TrustLevel.LIMITED},
            TrustLevel.STANDARD: {TrustLevel.SANDBOXED, TrustLevel.LIMITED, TrustLevel.STANDARD},
            TrustLevel.ELEVATED: {TrustLevel.LIMITED, TrustLevel.STANDARD, TrustLevel.ELEVATED},
            TrustLevel.ADMIN: set(TrustLevel),  # Can communicate with all
        }

    def set_trust_level(self, agent_id: str, level: TrustLevel):
        """Set agent trust level."""
        self._trust_levels[agent_id] = level

    def get_trust_level(self, agent_id: str) -> TrustLevel:
        """Get agent trust level."""
        return self._trust_levels.get(agent_id, TrustLevel.UNTRUSTED)

    def can_communicate(
        self,
        sender_id: str,
        recipient_id: str
    ) -> bool:
        """Check if sender can communicate with recipient."""
        sender_level = self.get_trust_level(sender_id)
        recipient_level = self.get_trust_level(recipient_id)

        allowed = self._allowed_communications.get(sender_level, set())
        return recipient_level in allowed

    def can_delegate_task(
        self,
        delegator_id: str,
        delegate_id: str
    ) -> bool:
        """Check if delegator can delegate tasks to delegate."""
        delegator_level = self.get_trust_level(delegator_id)
        delegate_level = self.get_trust_level(delegate_id)

        # Can only delegate to same or lower trust level
        return delegate_level <= delegator_level
```

---

## Quick Reference

### Sandboxing Decision Matrix

| Threat | Minimum Sandbox | Recommended |
|--------|-----------------|-------------|
| Memory exhaustion | Process limits | Container |
| CPU exhaustion | Process limits | Container |
| File system access | Path restrictions | Container (read-only) |
| Network exfiltration | Network namespace | Container + proxy |
| Code injection | RestrictedPython | Container |
| Privilege escalation | Drop capabilities | Container + seccomp |
| Inter-agent attacks | Signed messages | Separate containers |

### Container Security Checklist

```
□ Use non-root user
□ Drop all capabilities (--cap-drop=ALL)
□ Enable no-new-privileges
□ Use read-only filesystem
□ Disable network (--network=none) if not needed
□ Set memory and CPU limits
□ Limit PIDs
□ Use seccomp profile
□ Mount volumes read-only
□ Use tmpfs for temp storage
```
