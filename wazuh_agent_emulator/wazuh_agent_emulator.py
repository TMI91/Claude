#!/usr/bin/env python3
"""
Wazuh Agent Emulator
Simulates Wazuh 4.x agents: registration, event delivery, log replay, stress testing.

Run as Administrator when needed (some interfaces require elevated access).
"""

import argparse
import base64
import hashlib
import json
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

# ── Optional dependencies ─────────────────────────────────────────────────────

try:
    from Crypto.Cipher import Blowfish
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
    import io as _io
    console = Console(
        highlight=False,
        file=_io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace"),
    )
except ImportError:
    HAS_RICH = False

    class _FallbackConsole:
        def print(self, *a, **kw):
            print(*[str(x) for x in a])
        def log(self, *a, **kw):
            print(*[str(x) for x in a])

    console = _FallbackConsole()

# ── Protocol constants ────────────────────────────────────────────────────────

DEFAULT_MANAGER    = "127.0.0.1"
DEFAULT_REG_PORT   = 1515
DEFAULT_EVENT_PORT = 1514
DEFAULT_AGENT_NAME = "emulated-agent-xxxxx"
BLOWFISH_BLOCK     = 8
WAZUH_VERSION      = "v4.7.0"

# Synthetic syslog-style event templates
_TEMPLATES = [
    "sshd[{pid}]: Failed password for {user} from {src} port {port} ssh2",
    "sshd[{pid}]: Accepted publickey for {user} from {src} port {port} ssh2",
    "sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
    "kernel: [UFW BLOCK] IN=eth0 SRC={src} DST={dst} PROTO=TCP DPT={port}",
    "systemd[1]: Started Session {pid} of user {user}.",
    "cron[{pid}]: ({user}) CMD (/usr/bin/find /tmp -mtime +7 -delete)",
    "su[{pid}]: FAILED su for root by {user}",
    "auditd[{pid}]: audit_log_n_lost=1 audit_rate_limit=0",
    "sshd[{pid}]: Invalid user {user} from {src} port {port}",
    "kernel: usb 2-1: new high-speed USB device number {pid} using xhci_hcd",
    "postfix/smtpd[{pid}]: NOQUEUE: reject: RCPT from {src}[{src}]: 554 Relay access denied",
    "apache2: {src} - - [{ts}] \"GET /admin HTTP/1.1\" 403 512",
]

_USERS = ["admin", "ubuntu", "root", "pi", "oracle", "postgres", "deploy", "git"]
_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]


def _rand_ip() -> str:
    prefix = random.choice(["192.168.1", "10.0.0", "172.16.0"])
    return f"{prefix}.{random.randint(2, 254)}"


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class WazuhKey:
    agent_id:   str
    agent_name: str
    agent_ip:   str
    secret:     str

    # Official Wazuh key derivation (from development/message-format docs):
    #   filesum2 = MD5(secret)              → 32 hex chars
    #   filesum1 = MD5(MD5(name)+MD5(id))  → take first 15 hex chars
    #   enc_key  = filesum2 + filesum1      → 47 bytes (used as Blowfish key)
    def encryption_key(self) -> bytes:
        filesum2 = hashlib.md5(self.secret.encode()).hexdigest()          # 32 chars
        combined = (hashlib.md5(self.agent_name.encode()).hexdigest()
                    + hashlib.md5(self.agent_id.encode()).hexdigest())    # 64 chars
        filesum1 = hashlib.md5(combined.encode()).hexdigest()[:15]        # 15 chars
        return (filesum2 + filesum1).encode()                             # 47 bytes

    @classmethod
    def from_b64(cls, b64_str: str) -> "WazuhKey":
        raw = b64_str.strip()
        # Some managers return the key as base64; others send it as plain text.
        try:
            decoded = base64.b64decode(raw).decode()
        except Exception:
            decoded = raw
        parts = decoded.split(" ", 3)
        if len(parts) != 4:
            raise ValueError(f"Unexpected key format: {decoded!r}")
        return cls(*parts)

    def to_file(self, path: Path) -> None:
        path.write_text(json.dumps(
            {"agent_id": self.agent_id, "agent_name": self.agent_name,
             "agent_ip": self.agent_ip, "secret": self.secret},
            indent=2,
        ))

    @classmethod
    def from_file(cls, path: Path) -> "WazuhKey":
        return cls(**json.loads(path.read_text()))


@dataclass
class AgentStats:
    name:         str
    events_sent:  int   = 0
    bytes_sent:   int   = 0
    errors:       int   = 0
    connected:    bool  = False
    start_time:   float = field(default_factory=time.time)
    last_event:   Optional[str] = None


@dataclass
class ServerAgentStats:
    agent_id:    str
    agent_name:  str
    events_recv: int   = 0
    bytes_recv:  int   = 0
    connected:   bool  = False
    start_time:  float = field(default_factory=time.time)
    last_event:  Optional[str] = None


# ── Registration (TCP 1515) ───────────────────────────────────────────────────

class WazuhRegistrar:
    """Performs the Wazuh agent registration handshake on TCP port 1515."""

    def __init__(self, manager: str, port: int = DEFAULT_REG_PORT,
                 use_tls: bool = True, verify_cert: bool = False):
        self.manager     = manager
        self.port        = port
        self.use_tls     = use_tls
        self.verify_cert = verify_cert

    def register(self, agent_name: str, agent_ip: str = "any",
                 password: Optional[str] = None) -> WazuhKey:
        """Register agent on port 1515.

        If *password* is None the request is sent without one first.
        When the manager replies with "Invalid password" the method
        automatically retries with *password* if one was supplied, so the
        emulator works with both password-protected and open managers.
        """
        # Attempt registration; retry with password on auth failure.
        attempts = [None, password] if password else [None]
        last_err: Optional[str] = None

        for attempt_pwd in attempts:
            resp, buf = self._attempt_register(agent_name, attempt_pwd)
            if resp.startswith("OSSEC K:'"):
                b64 = resp[9:].rstrip("'")
                try:
                    return WazuhKey.from_b64(b64)
                except (UnicodeDecodeError, ValueError):
                    raise RuntimeError(
                        f"Key payload could not be decoded.\n"
                        f"  Raw response (repr): {resp!r}\n"
                        f"  Raw bytes (hex): {buf.hex()}"
                    )
            last_err = resp

        # All attempts failed — give an actionable error message.
        if "Invalid password" in (last_err or ""):
            raise RuntimeError(
                f"Manager requires a registration password.\n"
                f"  Pass --reg-password <pwd> and retry.\n"
                f"  (On the manager: sudo cat /var/ossec/etc/authd.pass)"
            )
        raise RuntimeError(f"Manager response: {last_err!r}")

    def _attempt_register(self, agent_name: str,
                          password: Optional[str]) -> tuple[str, bytes]:
        """Open a connection and send one registration request; return (response, raw_bytes)."""
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(15)
        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if not self.verify_cert:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=self.manager)
        else:
            sock = raw
        try:
            sock.connect((self.manager, self.port))
            # Password is sent as a leading prefix per Wazuh authd spec:
            # "OSSEC PASS: <pwd> OSSEC A:'<name>' ..."
            if password:
                req = f"OSSEC PASS: {password} OSSEC A:'{agent_name}' V:'{WAZUH_VERSION}'\n"
            else:
                req = f"OSSEC A:'{agent_name}' V:'{WAZUH_VERSION}'\n"
            sock.sendall(req.encode())
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return buf.decode(errors="replace").strip(), buf
        finally:
            sock.close()


# ── Message encryption ────────────────────────────────────────────────────────

class MessageCrypto:
    """Encrypts agent messages with Blowfish CBC (OSSEC/Wazuh wire format).

    Spec: https://documentation.wazuh.com/current/development/message-format.html
    Block  : {rand:05d}{global:010d}:{local:04d}:{event}
    Frame  : MD5(block) + block  →  zlib-deflate  →  pad '!' to 8-byte boundary
    Encrypt: Blowfish-CBC, fixed IV FE DC BA 98 76 54 32 10 (not prepended)
    Prefix : '!<ID>!:' for unrestricted agents (ip='any'), ':' for restricted
    TCP    : 4-byte little-endian length + prefix + ciphertext
    """

    # Fixed Blowfish IV per spec — NOT random, NOT transmitted
    _BF_IV = bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])

    def __init__(self, key: WazuhKey):
        if not HAS_CRYPTO:
            raise RuntimeError("pycryptodome required: pip install pycryptodome")
        self._enc_key  = key.encryption_key()
        self._agent_id = key.agent_id
        self._prefix   = f"!{key.agent_id}!:".encode()  # unrestricted (ip='any')
        self._global_counter = 0
        self._local_counter  = 0

    def encrypt(self, plaintext: str) -> bytes:
        self._global_counter += 1
        self._local_counter  += 1

        # 1. Build block
        rand  = random.randint(0, 65535)
        block = (f"{rand:05d}{self._global_counter:010d}"
                 f":{self._local_counter:04d}:{plaintext}").encode()

        # 2. Prepend MD5 of block
        md5_hex = hashlib.md5(block).hexdigest().encode()   # 32 bytes
        data    = md5_hex + block

        # 3. zlib deflate
        compressed = zlib.compress(data)

        # 4. Pad to Blowfish block boundary (8 bytes) with '!'
        rem = len(compressed) % BLOWFISH_BLOCK
        if rem:
            compressed = b"!" * (BLOWFISH_BLOCK - rem) + compressed

        # 5. Encrypt with fixed IV (CBC)
        cipher     = Blowfish.new(self._enc_key, Blowfish.MODE_CBC, self._BF_IV)
        ciphertext = cipher.encrypt(compressed)

        # 6. Return prefix + ciphertext (IV is fixed, not transmitted)
        return self._prefix + ciphertext


# ── Agent session (TCP 1514) ──────────────────────────────────────────────────

class WazuhAgentSession:
    """Manages a TCP connection to port 1514 and sends framed, encrypted events."""

    def __init__(self, manager: str, port: int, key: WazuhKey):
        self.manager = manager
        self.port    = port
        self.key     = key
        self.crypto  = MessageCrypto(key) if HAS_CRYPTO else None
        self._sock:  Optional[socket.socket] = None

    def connect(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(15)
        self._sock.connect((self.manager, self.port))
        # 1. Send startup message per spec: "#!-agent startup "
        self.send_event("#!-agent startup ")
        # 2. Read the manager's ACK (4-byte LE length + encrypted payload).
        #    Must drain the full response before sending events.
        try:
            hdr = self._recv_exact(4)
            if hdr:
                size = struct.unpack("<I", hdr)[0]
                self._recv_exact(size)  # discard encrypted ACK payload
        except OSError:
            pass  # ACK is optional; some manager versions don't send it

    def send_event(self, message: str) -> int:
        payload = self.crypto.encrypt(message) if self.crypto else message.encode()
        # TCP framing: 4-byte little-endian length prefix (per spec)
        frame   = struct.pack("<I", len(payload)) + payload
        self._write(frame)
        return len(frame)

    def _write(self, data: bytes) -> None:
        if not self._sock:
            raise RuntimeError("Not connected")
        sent = 0
        while sent < len(data):
            n = self._sock.send(data[sent:])
            if n == 0:
                raise ConnectionError("Socket closed by manager")
            sent += n

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes, handling partial reads."""
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None


# ── Event generation ──────────────────────────────────────────────────────────

class EventGenerator:
    """Produces synthetic syslog events or iterates over a log file."""

    def synthetic(self, hostname: str = "emulated-host") -> str:
        ts  = datetime.now().strftime("%b %d %H:%M:%S")
        msg = random.choice(_TEMPLATES).format(
            pid=random.randint(1000, 65535),
            user=random.choice(_USERS),
            src=_rand_ip(),
            dst=_rand_ip(),
            port=random.choice(_PORTS),
            ts=datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000"),
        )
        return f"{ts} {hostname} {msg}"

    @staticmethod
    def log_lines(path: Path) -> Iterator[str]:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if line:
                yield line


# ── Single-agent runner ───────────────────────────────────────────────────────

class AgentRunner:
    def __init__(self, manager: str, agent_name: str,
                 reg_port: int = DEFAULT_REG_PORT,
                 event_port: int = DEFAULT_EVENT_PORT,
                 key_file: Optional[Path] = None,
                 use_tls: bool = True,
                 reg_password: Optional[str] = None):
        self.manager      = manager
        self.agent_name   = agent_name
        self.reg_port     = reg_port
        self.event_port   = event_port
        self.key_file     = key_file
        self.use_tls      = use_tls
        self.reg_password = reg_password
        self.key: Optional[WazuhKey] = None

    def ensure_key(self) -> WazuhKey:
        if self.key_file and self.key_file.exists():
            self.key = WazuhKey.from_file(self.key_file)
            # Always use the name stored in the key file, not the CLI default.
            self.agent_name = self.key.agent_name
            console.log(f"Loaded key for agent {self.key.agent_id} ({self.key.agent_name})")
            return self.key

        console.log(f"Registering {self.agent_name} with {self.manager}:{self.reg_port}...")
        reg      = WazuhRegistrar(self.manager, self.reg_port, self.use_tls)
        self.key = reg.register(self.agent_name, password=self.reg_password)
        self.agent_name = self.key.agent_name   # normalise (manager may alter the name)
        console.log(f"Registered: ID={self.key.agent_id}")

        if self.key_file:
            self.key.to_file(self.key_file)
            console.log(f"Key saved → {self.key_file}")

        return self.key

    def run(self, stats: AgentStats, duration: Optional[float],
            rate: float, stop: threading.Event,
            log_file: Optional[Path] = None) -> None:
        key      = self.ensure_key()
        # Sync stats name with the real agent name (key file may differ from CLI default).
        stats.name = self.agent_name
        gen      = EventGenerator()
        source   = gen.log_lines(log_file) if log_file else None
        deadline = time.time() + duration if duration else None
        interval       = 1.0 / rate if rate > 0 else 0
        KEEPALIVE_SECS = 9
        RECONNECT_WAIT = 3

        while not stop.is_set():
            if deadline and time.time() >= deadline:
                break
            session = WazuhAgentSession(self.manager, self.event_port, key)
            try:
                session.connect()
                stats.connected  = True
                last_keepalive   = time.time()
                console.log(f"{self.agent_name}: connected (ID {key.agent_id})")

                while not stop.is_set():
                    if deadline and time.time() >= deadline:
                        return

                    now = time.time()
                    if now - last_keepalive >= KEEPALIVE_SECS:
                        session.send_event("#!-keep_alive ")
                        last_keepalive = now

                    if source is not None:
                        try:
                            event = next(source)
                        except StopIteration:
                            return
                    else:
                        event = gen.synthetic(hostname=self.agent_name)

                    n = session.send_event(event)
                    stats.events_sent += 1
                    stats.bytes_sent  += n
                    stats.last_event   = event[:72] + "…" if len(event) > 72 else event

                    if interval:
                        time.sleep(interval)

            except (OSError, ConnectionError, ssl.SSLError) as e:
                stats.errors  += 1
                stats.connected = False
                console.log(f"{self.agent_name}: connection lost ({e}) — reconnecting in {RECONNECT_WAIT}s")
                session.close()
                if not stop.is_set() and not (deadline and time.time() >= deadline):
                    time.sleep(RECONNECT_WAIT)
            except RuntimeError as e:
                stats.errors += 1
                console.log(f"{self.agent_name}: {e}")
                return
            finally:
                stats.connected = False
                session.close()


# ── Server: key store ────────────────────────────────────────────────────────

class ServerKeyStore:
    """Thread-safe registry of registered agents; optionally persisted to JSON."""

    def __init__(self, path: Optional[Path] = None):
        self._lock    = threading.Lock()
        self._agents: dict[str, WazuhKey] = {}   # agent_id → WazuhKey
        self._path    = path
        if path and path.exists():
            self._load()

    # ── public API ────────────────────────────────────────────────────────────

    def register(self, name: str, ip: str = "any") -> WazuhKey:
        """Create a new agent entry, assign the next free ID, return the key."""
        with self._lock:
            if any(k.agent_name == name for k in self._agents.values()):
                raise ValueError(f"Duplicate agent name: {name}")
            agent_id = self._next_id()
            secret   = os.urandom(32).hex()        # 64-char hex secret
            key      = WazuhKey(agent_id, name, ip, secret)
            self._agents[agent_id] = key
            self._save()
            return key

    def get(self, agent_id: str) -> Optional[WazuhKey]:
        with self._lock:
            return self._agents.get(agent_id)

    def all_keys(self) -> list[WazuhKey]:
        with self._lock:
            return list(self._agents.values())

    # ── private helpers ───────────────────────────────────────────────────────

    def _next_id(self) -> str:
        existing = {int(k) for k in self._agents}
        n = 1
        while n in existing:
            n += 1
        return f"{n:03d}"

    def _save(self) -> None:
        if not self._path:
            return
        data = {k: {"agent_id": v.agent_id, "agent_name": v.agent_name,
                    "agent_ip": v.agent_ip, "secret": v.secret}
                for k, v in self._agents.items()}
        self._path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        data = json.loads(self._path.read_text())
        self._agents = {k: WazuhKey(**v) for k, v in data.items()}


# ── Server: message crypto (shared with agent side) ───────────────────────────

class ServerMessageCrypto:
    """Encrypt/decrypt Wazuh messages on the server side (same algorithm as agent)."""

    _BF_IV = bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])

    def __init__(self, key: WazuhKey):
        if not HAS_CRYPTO:
            raise RuntimeError("pycryptodome required")
        self._enc_key = key.encryption_key()
        self._gcount  = random.randint(0, 9999)
        self._lcount  = 0

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a server-to-agent message (same wire format as agent-to-server)."""
        self._gcount += 1
        self._lcount += 1
        rand  = random.randint(0, 65535)
        block = (f"{rand:05d}{self._gcount:010d}"
                 f":{self._lcount:04d}:{plaintext}").encode()
        md5   = hashlib.md5(block).hexdigest().encode()
        comp  = zlib.compress(md5 + block)
        rem   = len(comp) % BLOWFISH_BLOCK
        if rem:
            comp = b"!" * (BLOWFISH_BLOCK - rem) + comp
        ct = Blowfish.new(self._enc_key, Blowfish.MODE_CBC, self._BF_IV).encrypt(comp)
        # Server responses use ":" prefix (restricted format per spec)
        return b":" + ct

    def decrypt(self, payload: bytes) -> Optional[str]:
        """Decrypt an agent-to-server payload (strip prefix, decrypt, decompress)."""
        # Strip prefix: ":"  or  "!<ID>!:"
        if payload.startswith(b"!"):
            try:
                second = payload.index(b"!", 1)
                ct = payload[second + 2:]          # skip "!ID!:"
            except ValueError:
                return None
        elif payload.startswith(b":"):
            ct = payload[1:]
        else:
            ct = payload

        if len(ct) % BLOWFISH_BLOCK != 0 or len(ct) == 0:
            return None
        try:
            raw = Blowfish.new(self._enc_key, Blowfish.MODE_CBC, self._BF_IV).decrypt(ct)
            raw = raw.lstrip(b"!")          # strip '!' padding
            dec = zlib.decompress(raw)
            # Format after decompression: MD5(32) + rand(5) + gcount(10) + ':' + lcount(4) + ':' + msg
            if len(dec) < 32 + 5 + 10 + 1 + 4 + 1:
                return None
            md5_recv  = dec[:32].decode(errors="replace")
            body      = dec[32:]
            md5_check = hashlib.md5(body).hexdigest()
            if md5_recv != md5_check:
                return None                 # checksum mismatch
            # body = rand(5) + gcount(10) + ':' + lcount(4) + ':' + message
            # skip first 5+10+1+4+1 = 21 bytes to get the actual message
            msg = body[21:].decode(errors="replace").rstrip("\x00")
            return msg
        except Exception:
            return None


# ── Server: registration listener (TCP 1515) ─────────────────────────────────

class WazuhRegistrationServer:
    """Listens on port 1515 and responds to OSSEC agent registration requests."""

    def __init__(self, bind: str, port: int, keystore: ServerKeyStore,
                 password: Optional[str] = None,
                 use_tls: bool = False,
                 cert_file: Optional[str] = None,
                 key_file_tls: Optional[str] = None):
        self.bind         = bind
        self.port         = port
        self.keystore     = keystore
        self.password     = password
        self.use_tls      = use_tls
        self.cert_file    = cert_file
        self.key_file_tls = key_file_tls
        self._server_sock: Optional[socket.socket] = None

    def start(self, stop: threading.Event) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind, self.port))
        self._server_sock.listen(16)
        self._server_sock.settimeout(1.0)
        console.log(f"[reg-server] Listening on {self.bind}:{self.port} (TLS={self.use_tls})")

        while not stop.is_set():
            try:
                conn, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=self._handle,
                args=(conn, addr),
                daemon=True,
            )
            t.start()

        self._server_sock.close()

    def _handle(self, conn: socket.socket, addr: tuple) -> None:
        if self.use_tls and self.cert_file and self.key_file_tls:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self.cert_file, self.key_file_tls)
                conn = ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError as e:
                console.log(f"[reg-server] TLS error from {addr}: {e}")
                conn.close()
                return

        try:
            conn.settimeout(15)
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk

            line = buf.decode(errors="replace").strip()

            # Extract optional password prefix: "OSSEC PASS: <pwd> OSSEC A:..."
            pwd_supplied: Optional[str] = None
            if line.startswith("OSSEC PASS:"):
                # Format: "OSSEC PASS: <pwd> OSSEC A:'name' ..."
                rest = line[len("OSSEC PASS:"):].lstrip(" ")
                # Find the "OSSEC A:" part after the password
                ossec_idx = rest.find("OSSEC ")
                if ossec_idx > 0:
                    pwd_supplied = rest[:ossec_idx].rstrip()
                    line         = rest[ossec_idx:]
                else:
                    self._send(conn, "ERROR: Invalid request format")
                    return

            # Validate password if server requires one
            if self.password:
                if pwd_supplied != self.password:
                    self._send(conn, "ERROR: Invalid passwordERROR: Unable to add agent")
                    console.log(f"[reg-server] {addr[0]}: rejected (wrong password)")
                    return

            # Parse "OSSEC A:'name'" (ignore V: and other optional fields)
            if "OSSEC A:'" not in line:
                self._send(conn, "ERROR: Invalid request")
                return
            start = line.index("OSSEC A:'") + 9
            end   = line.index("'", start)
            name  = line[start:end]

            # Register the agent
            try:
                key = self.keystore.register(name)
            except ValueError as e:
                self._send(conn, f"ERROR: {e}ERROR: Unable to add agent")
                console.log(f"[reg-server] {addr[0]}: {e}")
                return

            # Respond with key in plain-text format (matching real Wazuh behaviour)
            key_str = f"{key.agent_id} {key.agent_name} {key.agent_ip} {key.secret}"
            self._send(conn, f"OSSEC K:'{key_str}'")
            console.log(
                f"[reg-server] Registered {name!r} → ID={key.agent_id}  src={addr[0]}"
            )
        except Exception as e:
            console.log(f"[reg-server] Error handling {addr}: {e}")
        finally:
            conn.close()

    @staticmethod
    def _send(conn: socket.socket, msg: str) -> None:
        conn.sendall((msg + "\n").encode())


# ── Server: event listener (TCP 1514) ────────────────────────────────────────

class WazuhEventServer:
    """Listens on port 1514, decrypts agent messages, sends proper ACK/keep-alive."""

    KEEPALIVE_TIMEOUT = 10      # close connection if silent for >10 s

    def __init__(self, bind: str, port: int, keystore: ServerKeyStore,
                 event_log: Optional[Path] = None):
        self.bind      = bind
        self.port      = port
        self.keystore  = keystore
        self.event_log = event_log
        self._lock     = threading.Lock()
        self._stats:   dict[str, ServerAgentStats] = {}   # agent_id → stats
        self._server_sock: Optional[socket.socket] = None
        self._log_fh   = open(event_log, "a", encoding="utf-8") if event_log else None

    # ── public ────────────────────────────────────────────────────────────────

    def start(self, stop: threading.Event) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind, self.port))
        self._server_sock.listen(64)
        self._server_sock.settimeout(1.0)
        console.log(f"[event-server] Listening on {self.bind}:{self.port}")

        while not stop.is_set():
            try:
                conn, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=self._handle,
                args=(conn, addr),
                daemon=True,
            )
            t.start()

        if self._log_fh:
            self._log_fh.close()
        self._server_sock.close()

    def agent_stats(self) -> list[ServerAgentStats]:
        with self._lock:
            return list(self._stats.values())

    # ── per-connection handler ────────────────────────────────────────────────

    def _handle(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(self.KEEPALIVE_TIMEOUT)
        crypto: Optional[ServerMessageCrypto] = None
        agent_id: Optional[str] = None
        last_gcount = -1

        try:
            while True:
                # ── read one frame ──────────────────────────────────────────
                hdr = self._recv_exact(conn, 4)
                if not hdr:
                    break
                size = struct.unpack("<I", hdr)[0]
                if size == 0 or size > 65536:
                    break
                payload = self._recv_exact(conn, size)
                if not payload:
                    break

                # ── identify agent from prefix ──────────────────────────────
                if agent_id is None:
                    agent_id = self._extract_id(payload)
                    if not agent_id:
                        break
                    key = self.keystore.get(agent_id)
                    if not key:
                        console.log(
                            f"[event-server] {addr[0]}: unknown agent ID {agent_id!r}"
                        )
                        break
                    crypto = ServerMessageCrypto(key)
                    with self._lock:
                        if agent_id not in self._stats:
                            self._stats[agent_id] = ServerAgentStats(
                                agent_id=agent_id,
                                agent_name=key.agent_name,
                            )
                        self._stats[agent_id].connected = True
                    console.log(
                        f"[event-server] Agent {agent_id} ({key.agent_name}) connected from {addr[0]}"
                    )

                # ── decrypt ─────────────────────────────────────────────────
                msg = crypto.decrypt(payload) if crypto else None
                if msg is None:
                    # Could not decrypt — might be wrong key or corrupt frame
                    console.log(
                        f"[event-server] Agent {agent_id}: decrypt failed "
                        f"(payload {len(payload)}B)"
                    )
                    break

                with self._lock:
                    s = self._stats[agent_id]
                    s.bytes_recv += len(payload)

                # ── dispatch on message content ─────────────────────────────
                if msg.startswith("#!-agent startup"):
                    # Respond with ACK
                    ack_payload = crypto.encrypt("#!-agent ack ")
                    self._send_frame(conn, ack_payload)

                elif msg.startswith("#!-keep_alive"):
                    # Respond with keep-alive echo
                    ka_payload = crypto.encrypt("#!-keep_alive ")
                    self._send_frame(conn, ka_payload)

                else:
                    # Regular event — record and optionally log
                    with self._lock:
                        s = self._stats[agent_id]
                        s.events_recv += 1
                        s.last_event   = msg[:80] + "…" if len(msg) > 80 else msg
                    if self._log_fh:
                        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        self._log_fh.write(f"{ts} [{agent_id}] {msg}\n")
                        self._log_fh.flush()

        except socket.timeout:
            pass    # no message within KEEPALIVE_TIMEOUT — drop connection
        except (OSError, ConnectionError):
            pass
        finally:
            conn.close()
            if agent_id:
                with self._lock:
                    if agent_id in self._stats:
                        self._stats[agent_id].connected = False
                console.log(f"[event-server] Agent {agent_id} disconnected")

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_id(payload: bytes) -> Optional[str]:
        """Extract agent ID from payload prefix (!ID!: format)."""
        if not payload.startswith(b"!"):
            return None
        try:
            end = payload.index(b"!", 1)
            return payload[1:end].decode(errors="replace")
        except (ValueError, UnicodeDecodeError):
            return None

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _send_frame(conn: socket.socket, payload: bytes) -> None:
        conn.sendall(struct.pack("<I", len(payload)) + payload)


# ── Server: live display ──────────────────────────────────────────────────────

def _server_stats_table(
    srv: WazuhEventServer,
    keystore: ServerKeyStore,
    bind: str,
    reg_port: int,
    ev_port: int,
    title: str,
) -> "Panel":
    table = Table(show_header=True, header_style="bold green", border_style="dim")
    table.add_column("ID",          width=5)
    table.add_column("Agent",       style="cyan", min_width=20)
    table.add_column("Status",      width=8)
    table.add_column("Events",      justify="right", width=8)
    table.add_column("KB recv",     justify="right", width=8)
    table.add_column("ev/s",        justify="right", width=6)
    table.add_column("Last event",  style="dim", no_wrap=True, min_width=30)

    stats = {s.agent_id: s for s in srv.agent_stats()}
    all_keys = sorted(keystore.all_keys(), key=lambda k: k.agent_id)

    for key in all_keys:
        s = stats.get(key.agent_id)
        if s:
            elapsed = max(time.time() - s.start_time, 0.001)
            status  = Text("UP ", style="green") if s.connected else Text("-- ", style="dim")
            table.add_row(
                key.agent_id,
                key.agent_name,
                status,
                str(s.events_recv),
                f"{s.bytes_recv / 1024:.1f}",
                f"{s.events_recv / elapsed:.1f}",
                s.last_event or "—",
            )
        else:
            table.add_row(key.agent_id, key.agent_name,
                          Text("reg", style="dim"), "0", "0.0", "0.0", "—")

    total_ev = sum(s.events_recv for s in stats.values())
    total_kb = sum(s.bytes_recv  for s in stats.values()) / 1024
    connected = sum(1 for s in stats.values() if s.connected)
    table.caption = (
        f"Registered: {len(all_keys)}  Connected: {connected}  "
        f"Total events: {total_ev}  {total_kb:.1f} KB"
    )
    subtitle = f"reg:{bind}:{reg_port}  events:{bind}:{ev_port}"
    return Panel(table, title=f"[bold]{title}[/bold]",
                 subtitle=subtitle, border_style="green")


# ── Live display (agent side) ─────────────────────────────────────────────────

def _stats_table(all_stats: list[AgentStats], title: str) -> "Panel":
    table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    table.add_column("Agent",       style="cyan",  min_width=22)
    table.add_column("Status",      width=8)
    table.add_column("Events",      justify="right", width=8)
    table.add_column("KB sent",     justify="right", width=8)
    table.add_column("Errors",      justify="right", width=6)
    table.add_column("ev/s",        justify="right", width=6)
    table.add_column("Last event",  style="dim", no_wrap=True, min_width=30)

    for s in sorted(all_stats, key=lambda x: -x.events_sent)[:20]:
        elapsed = max(time.time() - s.start_time, 0.001)
        status  = Text("UP ", style="green") if s.connected else Text("-- ", style="dim")
        err_txt = Text(str(s.errors), style="red bold" if s.errors else "green")
        table.add_row(
            s.name, status, str(s.events_sent),
            f"{s.bytes_sent / 1024:.1f}", err_txt,
            f"{s.events_sent / elapsed:.1f}",
            s.last_event or "—",
        )

    total_ev = sum(s.events_sent for s in all_stats)
    total_kb = sum(s.bytes_sent for s in all_stats) / 1024
    table.caption = f"Total: {total_ev} events  {total_kb:.1f} KB"
    return Panel(table, title=f"[bold]{title}[/bold]", border_style="cyan")


# ── CLI ───────────────────────────────────────────────────────────────────────

HELP = """
Modes (agent):
  register   Register agent with manager and print/save key
  send       Send synthetic events (auto-registers if no key on file)
  replay     Replay a log file as events (--log-file required)
  stress     Spawn N agents simultaneously (--count)

Mode (server):
  server     Run a Wazuh manager emulator (ports 1515 + 1514)

Agent examples:
  python wazuh_agent_emulator.py --manager 10.0.0.1 --mode send --duration 60
  python wazuh_agent_emulator.py --manager 10.0.0.1 --mode register --save-key agent.json
  python wazuh_agent_emulator.py --manager 10.0.0.1 --mode replay --log-file /var/log/auth.log
  python wazuh_agent_emulator.py --manager 10.0.0.1 --mode stress --count 10 --rate 5 --duration 30

Server examples:
  python wazuh_agent_emulator.py --mode server
  python wazuh_agent_emulator.py --mode server --server-password s3cret --keystore keys.json
  python wazuh_agent_emulator.py --mode server --bind 0.0.0.0 --event-log events.log
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wazuh_agent_emulator",
        description="Simulate Wazuh 4.x agents and/or manager for testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP,
    )
    # ── shared ────────────────────────────────────────────────────────────────
    p.add_argument("--mode",         default="send",
                   choices=["register", "send", "replay", "stress", "server"])
    p.add_argument("--reg-port",     default=DEFAULT_REG_PORT,   type=int, metavar="PORT")
    p.add_argument("--event-port",   default=DEFAULT_EVENT_PORT, type=int, metavar="PORT")
    p.add_argument("--duration",     default=None, type=float, metavar="SECS",
                   help="Stop after N seconds (default: run until Ctrl+C)")

    # ── agent options ──────────────────────────────────────────────────────────
    ag = p.add_argument_group("agent options")
    ag.add_argument("--manager",      default=DEFAULT_MANAGER,    metavar="HOST")
    ag.add_argument("--agent-name",   default=DEFAULT_AGENT_NAME)
    ag.add_argument("--count",        default=5,    type=int,   metavar="N",
                    help="Number of agents (stress mode, default 5)")
    ag.add_argument("--rate",         default=1.0,  type=float, metavar="EV/S",
                    help="Events per second per agent (default 1.0)")
    ag.add_argument("--log-file",     default=None, metavar="PATH",
                    help="Log file to replay (--mode replay)")
    ag.add_argument("--save-key",     default=None, metavar="PATH",
                    help="Persist/load agent key as JSON file")
    ag.add_argument("--no-tls",       action="store_true",
                    help="Disable TLS on registration port 1515 (agent side)")
    ag.add_argument("--reg-password", default=None, metavar="PWD",
                    help="Registration password supplied by agent")

    # ── server options ─────────────────────────────────────────────────────────
    sv = p.add_argument_group("server options (--mode server)")
    sv.add_argument("--bind",            default="0.0.0.0", metavar="ADDR",
                    help="Address to bind (default 0.0.0.0)")
    sv.add_argument("--server-password", default=None, metavar="PWD",
                    help="Require this password for agent registration (optional)")
    sv.add_argument("--keystore",        default=None, metavar="PATH",
                    help="JSON file to persist registered agent keys")
    sv.add_argument("--event-log",       default=None, metavar="PATH",
                    help="Append received events to this file")
    sv.add_argument("--server-cert",     default=None, metavar="PATH",
                    help="TLS certificate for registration port (PEM)")
    sv.add_argument("--server-key",      default=None, metavar="PATH",
                    help="TLS private key for registration port (PEM)")
    return p


def main() -> None:
    # Show help when called with no arguments (or explicit help flags).
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ("?", "/?", "--?", "-?")):
        build_parser().print_help()
        sys.exit(0)

    args     = build_parser().parse_args()
    use_tls  = not args.no_tls
    stop     = threading.Event()
    key_file = Path(args.save_key) if args.save_key else None
    _start   = time.time()

    if not HAS_CRYPTO:
        console.print("Warning: pycryptodome not installed — events sent with plaintext framing (no Blowfish encryption)")

    try:
        # ── server ────────────────────────────────────────────────────────────
        if args.mode == "server":
            if not HAS_CRYPTO:
                sys.exit("pycryptodome required for server mode: pip install pycryptodome")

            keystore_path = Path(args.keystore) if args.keystore else None
            event_log     = Path(args.event_log) if args.event_log else None
            keystore      = ServerKeyStore(keystore_path)

            use_tls_srv   = bool(args.server_cert and args.server_key)
            reg_srv = WazuhRegistrationServer(
                bind         = args.bind,
                port         = args.reg_port,
                keystore     = keystore,
                password     = args.server_password,
                use_tls      = use_tls_srv,
                cert_file    = args.server_cert,
                key_file_tls = args.server_key,
            )
            ev_srv = WazuhEventServer(
                bind      = args.bind,
                port      = args.event_port,
                keystore  = keystore,
                event_log = event_log,
            )

            # Start both servers in background threads
            t_reg = threading.Thread(target=reg_srv.start, args=(stop,), daemon=True)
            t_ev  = threading.Thread(target=ev_srv.start,  args=(stop,), daemon=True)
            t_reg.start()
            t_ev.start()

            title = f"Wazuh Manager Emulator — {args.bind}"
            if HAS_RICH:
                with Live(refresh_per_second=2, console=console) as live:
                    while not stop.is_set():
                        if args.duration and time.time() >= _start + args.duration:
                            stop.set()
                            break
                        live.update(_server_stats_table(
                            ev_srv, keystore,
                            args.bind, args.reg_port, args.event_port,
                            title,
                        ))
                        time.sleep(0.5)
            else:
                while not stop.is_set():
                    time.sleep(1)

            t_reg.join(timeout=2)
            t_ev.join(timeout=2)
            return

        # ── register ──────────────────────────────────────────────────────────
        if args.mode == "register":
            reg = WazuhRegistrar(args.manager, args.reg_port, use_tls)
            key = reg.register(args.agent_name, password=args.reg_password)
            console.print(f"Registered  ID={key.agent_id}  Name={key.agent_name}  IP={key.agent_ip}")
            if key_file:
                key.to_file(key_file)
                console.print(f"Key saved → {key_file}")
            else:
                raw = f"{key.agent_id} {key.agent_name} {key.agent_ip} {key.secret}"
                console.print(f"Key (base64): {base64.b64encode(raw.encode()).decode()}")

        # ── send / replay ─────────────────────────────────────────────────────
        elif args.mode in ("send", "replay"):
            log_path = Path(args.log_file) if args.log_file else None
            if args.mode == "replay" and not log_path:
                sys.exit("--log-file is required for replay mode")
            if log_path and not log_path.exists():
                sys.exit(f"Log file not found: {log_path}")

            stats  = AgentStats(name=args.agent_name)
            runner = AgentRunner(
                manager=args.manager,
                agent_name=args.agent_name,
                reg_port=args.reg_port,
                event_port=args.event_port,
                key_file=key_file,
                use_tls=use_tls,
                reg_password=args.reg_password,
            )

            if HAS_RICH:
                with Live(refresh_per_second=4, console=console) as live:
                    t = threading.Thread(
                        target=runner.run,
                        args=(stats, args.duration, args.rate, stop, log_path),
                        daemon=True,
                    )
                    t.start()
                    while t.is_alive():
                        live.update(_stats_table([stats], f"Wazuh Agent Emulator — {args.manager}"))
                        time.sleep(0.25)
                    t.join()
                    live.update(_stats_table([stats], f"Wazuh Agent Emulator — {args.manager} (done)"))
            else:
                runner.run(stats, args.duration, args.rate, stop, log_path)
                print(f"Done: {stats.events_sent} events  {stats.bytes_sent} bytes  {stats.errors} errors")

        # ── stress ────────────────────────────────────────────────────────────
        elif args.mode == "stress":
            all_stats = [AgentStats(name=f"{args.agent_name}-{i:03d}") for i in range(args.count)]
            runners   = [
                AgentRunner(
                    manager=args.manager,
                    agent_name=s.name,
                    reg_port=args.reg_port,
                    event_port=args.event_port,
                    use_tls=use_tls,
                    reg_password=args.reg_password,
                )
                for s in all_stats
            ]
            threads = [
                threading.Thread(
                    target=r.run,
                    args=(s, args.duration, args.rate, stop, None),
                    daemon=True,
                )
                for r, s in zip(runners, all_stats)
            ]

            if HAS_RICH:
                with Live(refresh_per_second=4, console=console) as live:
                    for t in threads:
                        t.start()
                    while any(t.is_alive() for t in threads):
                        live.update(_stats_table(
                            all_stats,
                            f"Stress Test — {args.count} agents → {args.manager}",
                        ))
                        time.sleep(0.25)
                    for t in threads:
                        t.join()
                    live.update(_stats_table(
                        all_stats,
                        f"Stress Test — {args.count} agents → {args.manager} (done)",
                    ))
            else:
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                total = sum(s.events_sent for s in all_stats)
                print(f"Done: {args.count} agents  {total} total events")

    except KeyboardInterrupt:
        stop.set()
        console.print("\nStopped.")


if __name__ == "__main__":
    main()
