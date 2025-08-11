#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import os
import errno
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse
from datetime import timezone

import structlog
from structlog.dev import ConsoleRenderer
from structlog.stdlib import ProcessorFormatter

import configargparse

try:
    CFG_PARSER_CLASS = configargparse.YAMLConfigFileParser
    _YAML_ENABLED = True
except Exception:
    CFG_PARSER_CLASS = None
    _YAML_ENABLED = False

# Optional cryptography for richer cert parsing
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cryptography_available = True
except Exception:
    cryptography_available = False

# Keep pyOpenSSL as fallback for compatibility
try:
    from OpenSSL import crypto as openssl_crypto  # type: ignore
except Exception:
    openssl_crypto = None

# Optional SOCKS (PySocks) for socks5 proxies
try:
    import socks  # type: ignore
except Exception:
    socks = None

HTTP_EOL = b"\r\n"
HEADERS_END = b"\r\n\r\n"

# --------------------------- Duration parsing ---------------------------

_DUR_TOKEN = re.compile(r"(?P<num>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h|d)", re.IGNORECASE)
_UNIT_FACTORS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def parse_duration(value: str) -> float:
    """Parse '2m20s', '10m', '500ms', '1h5m30.5s' -> seconds (float). Bare numbers = seconds."""
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip().lower()
    try:
        return float(s)
    except ValueError:
        pass
    pos = 0
    total = 0.0
    for m in _DUR_TOKEN.finditer(s):
        if m.start() != pos:
            raise ValueError(f"Invalid duration syntax at: {s[pos:]}")
        num = float(m.group("num"))
        unit = m.group("unit").lower()
        total += num * _UNIT_FACTORS[unit]
        pos = m.end()
    if pos != len(s):
        raise ValueError(f"Invalid duration syntax at: {s[pos:]}")
    return total


# --------------------------- TLS cert helpers ---------------------------


def parse_cert_with_cryptography(der_bytes: bytes) -> dict:
    """Parse certificate using modern cryptography library (preferred method)."""
    cert = x509.load_der_x509_certificate(der_bytes)

    # Extract subject and issuer
    subject_parts = []
    for attribute in cert.subject:
        subject_parts.append(f"{attribute.oid._name}={attribute.value}")
    subject = "/".join(subject_parts)

    issuer_parts = []
    for attribute in cert.issuer:
        issuer_parts.append(f"{attribute.oid._name}={attribute.value}")
    issuer = "/".join(issuer_parts)

    # Extract Subject Alternative Names
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                sans.append(f"IP:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                sans.append(f"email:{name.value}")
            elif isinstance(name, x509.UniformResourceIdentifier):
                sans.append(f"URI:{name.value}")
            else:
                sans.append(str(name))
    except x509.ExtensionNotFound:
        pass

    # Extract dates and serial (use timezone-aware properties to avoid deprecation warnings)
    try:
        not_before_dt = cert.not_valid_before_utc
        not_after_dt = cert.not_valid_after_utc
    except AttributeError:
        # Fallback for older cryptography versions: assume UTC if naive
        nb = cert.not_valid_before
        na = cert.not_valid_after
        not_before_dt = nb if nb.tzinfo is not None else nb.replace(tzinfo=timezone.utc)
        not_after_dt = na if na.tzinfo is not None else na.replace(tzinfo=timezone.utc)

    not_before = not_before_dt.strftime("%Y%m%d%H%M%SZ")
    not_after = not_after_dt.strftime("%Y%m%d%H%M%SZ")
    serial = format(cert.serial_number, "x")
    fp_sha256 = hashlib.sha256(der_bytes).hexdigest().upper()

    return {
        "subject": subject,
        "issuer": issuer,
        "serial_hex": serial,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
        "fingerprint_sha256": fp_sha256,
    }


def _dnsname_matches(hostname: str, pattern: str) -> bool:
    """Minimal RFC 6125 DNS-ID matching with single-label wildcard support.
    - '*.example.com' matches 'www.example.com' but not 'a.b.example.com'
    - No wildcard matching for IDNA or non-DNS types handled here
    """
    hn = hostname.lower().rstrip(".")
    pat = pattern.lower().rstrip(".")
    if pat.startswith("*."):
        suffix = pat[2:]
        # Must have exactly one additional label
        if hn.endswith("." + suffix):
            return hn.count(".") == suffix.count(".") + 1
        return False
    return hn == pat


def _verify_hostname_from_cert_dict(
    cert_dict: dict, expected_hostname: str
) -> Tuple[bool, Optional[str]]:
    """Best-effort hostname verification using SANs or CN from getpeercert() dict."""
    if not cert_dict:
        return False, "empty_certificate"

    # Gather DNS names from SAN
    dns_names = []
    san = None
    if "subjectAltName" in cert_dict:
        san = cert_dict.get("subjectAltName")
    else:
        # Some implementations might vary case; be defensive
        for k, v in cert_dict.items():
            if isinstance(k, str) and k.lower() == "subjectaltname":
                san = v
                break
    if isinstance(san, (list, tuple)):
        for entry_type, value in san:
            if entry_type == "DNS" and isinstance(value, str):
                dns_names.append(value)

    # Fallback to CN if no SAN present
    if not dns_names:
        subject = cert_dict.get("subject", ())
        for rdn in subject:
            for key, value in rdn:
                if key == "commonName" and isinstance(value, str):
                    dns_names.append(value)

    if not dns_names:
        return False, "no_dns_names_in_cert"

    for name in dns_names:
        if _dnsname_matches(expected_hostname, name):
            return True, None

    return (
        False,
        f"hostname_mismatch: expected {expected_hostname}, cert_names={dns_names}",
    )


def parse_cert_with_pyopenssl(der_bytes: bytes) -> dict:
    """Parse certificate using pyOpenSSL (fallback method)."""
    x = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_ASN1, der_bytes)
    subject = "/".join(
        f"{k.decode()}={v.decode()}" for k, v in x.get_subject().get_components()
    )
    issuer = "/".join(
        f"{k.decode()}={v.decode()}" for k, v in x.get_issuer().get_components()
    )
    sans = []
    for i in range(x.get_extension_count()):
        ext = x.get_extension(i)
        if ext.get_short_name().decode().lower() == "subjectaltname":
            sans = [p.strip() for p in ext.__str__().split(",")]
            break
    not_before = x.get_notBefore().decode("ascii")
    not_after = x.get_notAfter().decode("ascii")
    serial = format(x.get_serial_number(), "x")
    fp_sha256 = hashlib.sha256(der_bytes).hexdigest().upper()
    return {
        "subject": subject,
        "issuer": issuer,
        "serial_hex": serial,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
        "fingerprint_sha256": fp_sha256,
    }


def parse_cert_basic(der_bytes: bytes, cert_dict: Optional[dict]) -> dict:
    subject = issuer = None
    sans = []
    not_before = not_after = None
    if cert_dict:

        def dn_to_str(dn):
            parts = []
            for rdn in dn:
                for k, v in rdn:
                    parts.append(f"{k}={v}")
            return "/".join(parts) if parts else None

        subject = dn_to_str(cert_dict.get("subject", []))
        issuer = dn_to_str(cert_dict.get("issuer", []))
        for k, v in cert_dict.items():
            if k.lower() == "subjectaltname":
                sans = [f"{t}:{n}" for t, n in v]
                break
        not_before = cert_dict.get("notBefore")
        not_after = cert_dict.get("notAfter")
    fp_sha256 = hashlib.sha256(der_bytes).hexdigest().upper() if der_bytes else None
    return {
        "subject": subject,
        "issuer": issuer,
        "serial_hex": None,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
        "fingerprint_sha256": fp_sha256,
    }


def extract_cert_details(
    ssl_sock: ssl.SSLSocket, verify_hostname: Optional[str]
) -> dict:
    """Return parsed cert details and whether it matches verify_hostname (SNI/URL host)."""
    cert_dict = {}
    try:
        cert_dict = ssl_sock.getpeercert() or {}
    except Exception:
        cert_dict = {}
    der = b""
    try:
        der = ssl_sock.getpeercert(binary_form=True) or b""
    except Exception:
        der = b""
    hostname_ok = None
    hostname_error = None
    if verify_hostname:
        # Use internal verifier to avoid deprecated ssl.match_hostname
        ok, err = _verify_hostname_from_cert_dict(cert_dict, verify_hostname)
        hostname_ok = ok
        hostname_error = err
    if der and cryptography_available:
        parsed = parse_cert_with_cryptography(der)
    elif der and openssl_crypto is not None:
        parsed = parse_cert_with_pyopenssl(der)
    else:
        parsed = parse_cert_basic(der, cert_dict or None)
    parsed["hostname_to_verify"] = verify_hostname
    parsed["hostname_ok"] = hostname_ok
    parsed["hostname_error"] = hostname_error
    return parsed


# --------------------------- Proxy config -------------------------------


class ProxyConfig:
    def __init__(
        self,
        scheme: str,
        host: str,
        port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.scheme = scheme  # 'http' | 'socks5'
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    @property
    def basic_auth_header(self) -> Optional[str]:
        if self.scheme != "http" or self.username is None:
            return None
        token = f"{self.username}:{self.password or ''}".encode()
        return "Basic " + base64.b64encode(token).decode()


def parse_proxy(proxy_url: Optional[str]) -> Optional[ProxyConfig]:
    if not proxy_url:
        return None
    pu = urlparse(proxy_url)
    scheme = pu.scheme.lower() if pu.scheme else ""
    if scheme in ("sock5", "socks5", "socks5h"):  # accept common typo 'sock5'
        if socks is None:
            raise RuntimeError(
                "SOCKS5 requested but PySocks is not installed. pip install PySocks"
            )
        host = pu.hostname
        port = pu.port or 1080
        if not host:
            raise ValueError("Invalid socks5 proxy URL.")
        return ProxyConfig("socks5", host, port, pu.username, pu.password)
    elif scheme == "http":
        host = pu.hostname
        port = pu.port or 8080
        if not host:
            raise ValueError("Invalid http proxy URL.")
        return ProxyConfig("http", host, port, pu.username, pu.password)
    else:
        raise ValueError("Unsupported proxy scheme. Use http:// or socks5://")


# --------------------------- Networking --------------------------------


def read_until_double_crlf(sock: socket.socket, max_bytes: int = 65536) -> bytes:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if HEADERS_END in data:
            break
        if len(data) > max_bytes:
            break
    return data


def parse_status_line(head: bytes) -> Tuple[Optional[int], str]:
    try:
        first_line = head.split(HTTP_EOL, 1)[0].decode("iso-8859-1", errors="replace")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1]), first_line
    except Exception:
        pass
    return None, ""


def connect_direct(host_or_ip: str, port: int, timeout_s: float) -> socket.socket:
    # create_connection handles IPv4/IPv6 and respects IP literals
    s = socket.create_connection((host_or_ip, port), timeout=timeout_s)
    s.settimeout(timeout_s)
    return s


def connect_via_socks5(
    proxy: ProxyConfig, host: str, port: int, timeout_s: float
) -> socket.socket:
    assert socks is not None
    s = socks.socksocket()
    s.set_proxy(
        proxy_type=socks.SOCKS5,
        addr=proxy.host,
        port=proxy.port,
        username=proxy.username,
        password=proxy.password,
    )
    s.settimeout(timeout_s)
    s.connect((host, port))  # target host:port through SOCKS
    return s


def http_connect_tunnel(
    sock: socket.socket, target_host: str, target_port: int, proxy_auth: Optional[str]
) -> Tuple[Optional[int], str, bytes]:
    req = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
        "Proxy-Connection: keep-alive",
    ]
    if proxy_auth:
        req.append(f"Proxy-Authorization: {proxy_auth}")
    req.append("")
    req.append("")
    raw = "\r\n".join(req).encode("ascii")
    sock.sendall(raw)
    head = read_until_double_crlf(sock)
    code, line = parse_status_line(head)
    if code != 200:
        raise OSError(f"Proxy CONNECT failed: {line or head[:80]!r}")
    return code, line, head


def send_minimal_http(
    sock: socket.socket,
    host: str,
    path: str,
    method: str = "HEAD",
    proxy_mode: bool = False,
    full_url: Optional[str] = None,
    proxy_auth: Optional[str] = None,
):
    target = full_url if (proxy_mode and full_url) else (path or "/")
    headers = [
        f"{method} {target} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
        "User-Agent: url-monitor/1.5",
    ]
    if proxy_mode and proxy_auth:
        headers.append(f"Proxy-Authorization: {proxy_auth}")
    headers.append("")
    headers.append("")
    sock.sendall("\r\n".join(headers).encode("ascii"))
    head = read_until_double_crlf(sock)
    return parse_status_line(head)


# --------------------------- Logging setup ------------------------------


def setup_logging(log_file: Optional[Path], log_format: str):
    """Configure logging so that file logs are always JSON while console respects selected format."""
    # Processor to abbreviate any absolute paths under HOME to '~' or '~/...'.
    # Applies recursively to dicts/lists/tuples.
    def abbreviate_home_paths(_logger, _method_name, event_dict):
        home_path = Path.home()
        home_str = str(home_path)
        home_prefix = home_str + os.sep

        def _abbrev(obj):
            if isinstance(obj, dict):
                return {k: _abbrev(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_abbrev(v) for v in obj]
            if isinstance(obj, tuple):
                return tuple(_abbrev(v) for v in obj)
            if isinstance(obj, Path):
                # Exact home -> '~'
                try:
                    rel = obj.relative_to(home_path)
                    if rel.as_posix() == ".":
                        return "~"
                    return "~/" + rel.as_posix()
                except Exception:
                    return str(obj)
            if isinstance(obj, str):
                if obj == home_str:
                    return "~"
                if obj.startswith(home_prefix):
                    return "~/" + obj[len(home_prefix):].replace(os.sep, "/")
            return obj

        for key, val in list(event_dict.items()):
            event_dict[key] = _abbrev(val)
        return event_dict
    # Handlers
    console_handler = logging.StreamHandler(sys.stdout)

    file_handler = None
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            str(log_file), maxBytes=5_000_000, backupCount=3
        )

    # Common pre-chain for console: enrich events before rendering
    pre_chain_console = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Console renderer depends on desired on-screen format
    if log_format == "console":
        console_processor = ConsoleRenderer(colors=True)
    elif log_format == "json":
        console_processor = structlog.processors.JSONRenderer()
    else:
        console_processor = structlog.processors.KeyValueRenderer(
            key_order=["ts", "level", "event"]
        )

    console_handler.setFormatter(
        ProcessorFormatter(
            processor=console_processor, foreign_pre_chain=pre_chain_console
        )
    )

    # File handler always JSON
    if file_handler is not None:
        file_handler.setFormatter(
            ProcessorFormatter(
                processor=structlog.processors.JSONRenderer(),
                foreign_pre_chain=pre_chain_console,
            )
        )

    handlers = [console_handler]
    if file_handler is not None:
        handlers.append(file_handler)

    logging.basicConfig(level=logging.INFO, handlers=handlers)

    # Configure structlog to hand off rendering to the ProcessorFormatter
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            abbreviate_home_paths,
            ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    return structlog.get_logger("url_monitor")


# --------------------------- Checker -----------------------------------


def check_once(
    target_url: str,
    timeout_s: float,
    log,
    proxy_cfg: Optional[ProxyConfig],
    method: str,
    connect_ip: Optional[str],
    ca_bundle: Optional[str],
):
    u = urlparse(target_url)
    if u.scheme not in ("http", "https"):
        log.error("unsupported_scheme", url=target_url, scheme=u.scheme)
        return

    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    if not host:
        log.error("invalid_url", url=target_url)
        return

    # SNI is always the URL hostname now
    tls_sni = host

    start = time.perf_counter()
    tcp_start = start
    sock = None
    via_proxy = bool(proxy_cfg)
    proxy_scheme = proxy_cfg.scheme if proxy_cfg else None

    try:
        # Establish TCP (direct / HTTP proxy / SOCKS5)
        if proxy_cfg and proxy_cfg.scheme == "http":
            # connect-ip ignored
            if connect_ip:
                structlog.get_logger().info(
                    "connect_ip_ignored_due_to_proxy",
                    reason="http_proxy_in_use",
                    connect_ip=connect_ip,
                )
            sock = connect_direct(proxy_cfg.host, proxy_cfg.port, timeout_s)

        elif proxy_cfg and proxy_cfg.scheme == "socks5":
            # connect-ip ignored
            if connect_ip:
                structlog.get_logger().info(
                    "connect_ip_ignored_due_to_proxy",
                    reason="socks5_proxy_in_use",
                    connect_ip=connect_ip,
                )
            sock = connect_via_socks5(
                proxy_cfg, host, port, timeout_s
            )  # to target host

        else:
            # Direct; honor connect_ip override if provided
            target_connect_host = connect_ip if connect_ip else host
            sock = connect_direct(target_connect_host, port, timeout_s)

        tcp_ms = int((time.perf_counter() - tcp_start) * 1000)

        if u.scheme == "https":
            if proxy_cfg and proxy_cfg.scheme == "http":
                try:
                    http_connect_tunnel(sock, host, port, proxy_cfg.basic_auth_header)
                except OSError as e:
                    structlog.get_logger().error(
                        "proxy_connect_error",
                        url=target_url,
                        via_proxy=via_proxy,
                        proxy_scheme=proxy_scheme,
                        message=str(e),
                    )
                    raise

            # TLS handshake with optional custom CA; SNI from URL host
            tls_start = time.perf_counter()
            if ca_bundle:
                ctx = ssl.create_default_context(
                    purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_bundle
                )
            else:
                ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = False  # we'll log match vs tls_sni
            ctx.verify_mode = ssl.CERT_REQUIRED

            ssock = ctx.wrap_socket(sock, server_hostname=tls_sni)
            tls_ms = int((time.perf_counter() - tls_start) * 1000)

            proto = ssock.version()
            cipher = ssock.cipher()
            cert_info = extract_cert_details(ssock, verify_hostname=tls_sni)

            status_code, status_line = send_minimal_http(
                ssock, host, path, method=method, proxy_mode=False
            )
            ssock.close()

            structlog.get_logger().info(
                "https_check",
                url=target_url,
                host=host,
                port=port,
                via_proxy=via_proxy,
                proxy_scheme=proxy_scheme,
                connect_ip=connect_ip if not via_proxy else None,
                tcp_ms=tcp_ms,
                tls_ms=tls_ms,
                tls_protocol=proto,
                tls_cipher=(cipher[0] if cipher else None),
                http_status=status_code,
                http_status_line=status_line,
                tls_sni=tls_sni,
                ca_bundle=ca_bundle,
                cert=cert_info,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        else:
            # HTTP (plaintext)
            proxy_mode_for_http = bool(proxy_cfg and proxy_cfg.scheme == "http")
            status_code, status_line = send_minimal_http(
                sock,
                host,
                path,
                method=method,
                proxy_mode=proxy_mode_for_http,
                full_url=target_url,
                proxy_auth=(
                    proxy_cfg.basic_auth_header if proxy_mode_for_http else None
                ),
            )
            sock.close()
            structlog.get_logger().info(
                "http_check",
                url=target_url,
                host=host,
                port=port,
                via_proxy=via_proxy,
                proxy_scheme=proxy_scheme,
                connect_ip=connect_ip if not via_proxy else None,
                tcp_ms=tcp_ms,
                http_status=status_code,
                http_status_line=status_line,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )

    except ConnectionResetError as e:
        structlog.get_logger().error(
            "tcp_error",
            tcp_event="ECONNRESET",
            url=target_url,
            via_proxy=via_proxy,
            proxy_scheme=proxy_scheme,
            errno=getattr(e, "errno", errno.ECONNRESET),
            message=str(e),
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    except socket.timeout as e:
        structlog.get_logger().error(
            "tcp_error",
            tcp_event="ETIMEDOUT",
            url=target_url,
            via_proxy=via_proxy,
            proxy_scheme=proxy_scheme,
            errno=getattr(e, "errno", errno.ETIMEDOUT),
            message="timeout",
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    except OSError as e:
        err_map = {
            errno.ECONNREFUSED: "ECONNREFUSED",
            errno.EHOSTUNREACH: "EHOSTUNREACH",
            errno.ENETUNREACH: "ENETUNREACH",
            errno.ECONNABORTED: "ECONNABORTED",
            errno.EPIPE: "EPIPE",
        }
        ev = err_map.get(getattr(e, "errno", None), "OSERROR")
        structlog.get_logger().error(
            "tcp_error",
            tcp_event=ev,
            url=target_url,
            via_proxy=via_proxy,
            proxy_scheme=proxy_scheme,
            errno=getattr(e, "errno", None),
            message=str(e),
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    except ssl.SSLError as e:
        structlog.get_logger().error(
            "tls_error",
            url=target_url,
            via_proxy=via_proxy,
            proxy_scheme=proxy_scheme,
            reason=getattr(e, "reason", None),
            message=str(e),
            tls_sni=tls_sni,
            ca_bundle=ca_bundle,
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    except Exception as e:
        structlog.get_logger().error(
            "unexpected_error",
            url=target_url,
            via_proxy=via_proxy,
            proxy_scheme=proxy_scheme,
            exception=type(e).__name__,
            message=str(e),
            tls_sni=(tls_sni if u.scheme == "https" else None),
            ca_bundle=ca_bundle,
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )
        try:
            if sock:
                sock.close()
        except Exception:
            pass


# --------------------------- CLI & main --------------------------------


def setup_parser(DEFAULT_BD: Path, DEFAULT_CFG: Path) -> configargparse.ArgParser:
    kwargs = {"default_config_files": [str(DEFAULT_CFG)]}
    if CFG_PARSER_CLASS is not None:
        kwargs["config_file_parser_class"] = CFG_PARSER_CLASS

    p = configargparse.ArgParser(
        description="Periodic URL monitor with TCP/TLS logging, proxies, DNS override, and custom CA.",
        prog="url_monitor",
        **kwargs,
    )
    p.add(
        "-c",
        "--config",
        is_config_file=True,
        help=f"Config file path (default: {DEFAULT_CFG})",
    )

    p.add("url_pos", nargs="?", help="URL to check (http or https) if not using --url")
    p.add("--url", env_var="URLMONITOR_URL", help="URL to check (http or https)")

    p.add(
        "--interval",
        env_var="URLMONITOR_INTERVAL",
        default=None,
        help="Interval between checks (e.g., 30s, 2m20s, 1h). If omitted, runs once and exits",
    )
    p.add(
        "--timeout",
        env_var="URLMONITOR_TIMEOUT",
        default="5s",
        help="Socket/TLS timeout (e.g., 750ms, 10s, 2m). Default: 5s",
    )

    p.add(
        "--proxy",
        env_var="URLMONITOR_PROXY",
        help="Proxy URL, e.g., http://user:pass@host:8080 or socks5://user:pass@host:1080",
    )

    p.add(
        "--method",
        choices=["HEAD", "GET"],
        env_var="URLMONITOR_METHOD",
        default="GET",
        help="HTTP method for probe",
    )

    p.add(
        "--log-format",
        choices=["json", "kv", "console"],
        env_var="URLMONITOR_LOG_FORMAT",
        default="console",
        help="Log output format",
    )
    p.add(
        "--log-file",
        env_var="URLMONITOR_LOG_FILE",
        help="Explicit log file path (overrides data-dir default)",
    )
    p.add(
        "--data-dir",
        env_var="URLMONITOR_DATA_DIR",
        default=str(DEFAULT_BD),
        help=f"Base app directory (default: {DEFAULT_BD}). Logs go to <data-dir>/logs",
    )

    # NEW: DNS override for direct connections
    p.add(
        "--connect-ip",
        env_var="URLMONITOR_CONNECT_IP",
        help="IPv4/IPv6 to connect to instead of resolving the URL host (direct connections only)",
    )

    # CA bundle path (kept)
    p.add(
        "--ca-bundle",
        env_var="URLMONITOR_CA_BUNDLE",
        help="Path to CA bundle file used to verify the server certificate",
    )

    return p


def main():
    HOME = Path.home()
    DEFAULT_BD = HOME / ".config" / "urlmonitor"
    DEFAULT_CFG = DEFAULT_BD / "config.yaml"

    p = setup_parser(DEFAULT_BD, DEFAULT_CFG)
    args = p.parse_args()

    if (
        args.config and str(args.config).lower().endswith((".yml", ".yaml"))
    ) and not _YAML_ENABLED:
        print(
            "Warning: Using a YAML config file but PyYAML is not installed. Install pyyaml.",
            file=sys.stderr,
        )

    target_url = args.url or args.url_pos
    if not target_url:
        p.error("No URL specified. Use --url or positional URL, or set URLMONITOR_URL.")

    # Validate CA bundle path (if provided)
    ca_bundle = args.ca_bundle
    if ca_bundle:
        ca_path = Path(ca_bundle).expanduser()
        if not ca_path.exists():
            print(f"CA bundle not found: {ca_path}", file=sys.stderr)
            sys.exit(2)
        ca_bundle = str(ca_path)

    try:
        interval_s = None if args.interval is None else parse_duration(args.interval)
        timeout_s = parse_duration(args.timeout)
        if timeout_s <= 0 or (interval_s is not None and interval_s <= 0):
            raise ValueError("Durations must be > 0")
    except Exception as e:
        print(f"Bad duration: {e}", file=sys.stderr)
        sys.exit(2)

    data_dir = Path(args.data_dir).expanduser()
    logs_dir = data_dir / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_file: Optional[Path]
    if args.log_file:
        log_file = Path(args.log_file).expanduser()
    else:
        log_file = logs_dir / "monitor.log"

    log = setup_logging(log_file, args.log_format)

    try:
        proxy_cfg = parse_proxy(args.proxy) if args.proxy else None
    except Exception as e:
        structlog.get_logger().error("bad_proxy", message=str(e))
        sys.exit(2)

    structlog.get_logger().info(
        "start",
        url=target_url,
        interval=(args.interval if args.interval is not None else None),
        interval_s=interval_s,
        timeout=args.timeout,
        timeout_s=timeout_s,
        via_proxy=bool(proxy_cfg),
        proxy_scheme=(proxy_cfg.scheme if proxy_cfg else None),
        log_format=args.log_format,
        method=args.method,
        data_dir=str(data_dir),
        log_file=str(log_file) if log_file else None,
        config_file=args.config,
        connect_ip=(args.connect_ip or None),
        ca_bundle=ca_bundle,
    )

    try:
        # Run once when no interval provided
        if interval_s is None:
            check_once(
                target_url,
                timeout_s,
                log,
                proxy_cfg,
                method=args.method,
                connect_ip=(args.connect_ip or None),
                ca_bundle=ca_bundle,
            )
        else:
            while True:
                check_once(
                    target_url,
                    timeout_s,
                    log,
                    proxy_cfg,
                    method=args.method,
                    connect_ip=(args.connect_ip or None),
                    ca_bundle=ca_bundle,
                )
                time.sleep(interval_s)
    except KeyboardInterrupt:
        structlog.get_logger().info("stop", url=target_url)


if __name__ == "__main__":
    main()
