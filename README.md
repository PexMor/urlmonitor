# URL Monitor

A low-level, dependency-light HTTP/HTTPS monitor that makes real TCP/TLS connections, supports HTTP and SOCKS5 proxies, optional DNS overrides, and custom CA bundles. It logs timing, protocol, cipher, HTTP status, and rich certificate details for HTTPS.

## Key features

- **Direct, HTTP proxy (CONNECT), or SOCKS5** connectivity
- **TLS details**: protocol, cipher, certificate subject/issuer/SANs/serial/fingerprint
- **Hostname verification**: internal verifier (wildcard-aware) logged as part of cert info
- **Configurable intervals** with duration strings (e.g., 750ms, 10s, 2m, 1h)
- **Run-once mode**: if `--interval` is omitted, runs a single check and exits
- **Custom CA bundle** support
- **Structured logging** with JSON, KV, or colorful console output
- **Log file rotation** in `~/.config/urlmonitor/logs`

## How it works (HTTPS)

1. Resolves and opens a TCP connection either directly, via HTTP proxy (and issues CONNECT), or via SOCKS5.
2. Establishes a TLS session using SNI set to the URL hostname.
3. Parses the peer certificate using the `cryptography` library (falls back to pyOpenSSL if needed) and computes SHA-256 fingerprint.
4. Performs a minimal HTTP request (HEAD/GET) and captures the response status.
5. Logs a structured record including timings and TLS/cert info.

For HTTP (non-TLS), a minimal HTTP request is sent directly or to the HTTP proxy (absolute-form URL) and the response status is logged.

## Installation

- Recommended: sync project dependencies

```bash
uv sync
```

- Requires Python 3.13+ (per `pyproject.toml`).

## Usage

- Run once (no interval):

```bash
uv run python urlmonitor.py --url https://example.com --timeout 5s
```

- Periodic monitoring:

```bash
uv run python urlmonitor.py --url https://example.com --timeout 5s --interval 60s
```

- Alternatively, use the helper wrapper script:

```bash
./murl --url https://example.com --timeout 5s --interval 60s
```

If needed, make it executable first: `chmod +x ./murl`.

## Parameters

| Flag                 | Env var                 | Type / Default                             | Description                                                                                                                                                    | Example                                    |
| -------------------- | ----------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `-c, --config`       | —                       | Path (none)                                | Optional config file (YAML supported if PyYAML installed). Defaults to `~/.config/urlmonitor/config.yaml` if present.                                          | `--config ./config.yaml`                   |
| positional `url_pos` | `URLMONITOR_URL`        | String (none)                              | URL to check (http or https). If both positional and `--url` are set, `--url` wins.                                                                            | `https://example.com`                      |
| `--url`              | `URLMONITOR_URL`        | String (none)                              | URL to check (http or https).                                                                                                                                  | `--url https://example.com`                |
| `--interval`         | `URLMONITOR_INTERVAL`   | Duration (none)                            | Interval between checks. If omitted, runs once and exits.                                                                                                      | `--interval 30s`                           |
| `--timeout`          | `URLMONITOR_TIMEOUT`    | Duration (`5s`)                            | Socket/TLS timeout.                                                                                                                                            | `--timeout 750ms`                          |
| `--proxy`            | `URLMONITOR_PROXY`      | String (none)                              | Proxy URL. Supports `http://user:pass@host:port` and `socks5://user:pass@host:port`.                                                                           | `--proxy http://user:pass@127.0.0.1:8080`  |
| `--method`           | `URLMONITOR_METHOD`     | `HEAD` or `GET` (`GET`)                    | HTTP method used for the probe.                                                                                                                                | `--method GET`                             |
| `--log-format`       | `URLMONITOR_LOG_FORMAT` | one of `json`, `kv`, `console` (`console`) | Log output format.                                                                                                                                             | `--log-format console`                     |
| `--log-file`         | `URLMONITOR_LOG_FILE`   | Path (default under data dir)              | Explicit log file path; otherwise logs to `~/.config/urlmonitor/logs/monitor.log`.                                                                             | `--log-file ./monitor.log`                 |
| `--data-dir`         | `URLMONITOR_DATA_DIR`   | Path (`~/.config/urlmonitor`)              | Base data directory; logs are saved under `<data-dir>/logs`.                                                                                                   | `--data-dir ~/.config/urlmonitor`          |
| `--connect-ip`       | `URLMONITOR_CONNECT_IP` | IPv4/IPv6 (none)                           | For direct connections only, connect to this literal IP instead of resolving the URL hostname (SNI still uses the URL hostname). Ignored when a proxy is used. | `--connect-ip 93.184.216.34`               |
| `--ca-bundle`        | `URLMONITOR_CA_BUNDLE`  | Path (none)                                | Custom CA bundle path for TLS verification.                                                                                                                    | `--ca-bundle /etc/ssl/certs/ca-bundle.crt` |

Notes:

- Durations accept `ms`, `s`, `m`, `h`, `d` (e.g., `500ms`, `2m30s`, `1h`). Bare numbers are treated as seconds.
- Exit status `2` is used for configuration/validation errors (e.g., bad duration, missing CA bundle path, bad proxy URL).

## Configuration file (YAML)

If `PyYAML` is installed, you can use a YAML config and invoke with `--config` (or rely on the default path if present). Keys are the long option names:

```yaml
url: https://httpbin.org/get
timeout: 5s
# interval omitted -> run once
method: HEAD
log-format: kv
data-dir: ~/.config/urlmonitor
# log-file: ./monitor.log
# proxy: http://user:pass@127.0.0.1:8080
# connect-ip: 93.184.216.34
# ca-bundle: /etc/ssl/certs/ca-bundle.crt
```

## Proxy behavior

- **HTTP proxy**: For HTTPS targets, the monitor sends `CONNECT host:port` first, then negotiates TLS through the tunnel. For HTTP targets, it sends an absolute-form request to the proxy. If `user:pass` is present in the proxy URL, `Proxy-Authorization: Basic …` is added automatically.
- **SOCKS5**: The monitor connects to the target host:port via the SOCKS5 proxy. Authentication is supported when provided in the URL.
- `--connect-ip` is ignored when any proxy is configured.

## TLS and certificate logging

- TLS is negotiated with SNI set to the URL hostname.
- Certificate fields logged: `subject`, `issuer`, `serial_hex`, `not_before`, `not_after`, `sans`, `fingerprint_sha256`.
- Hostname verification is performed internally (supports single-label wildcards like `*.example.com`) and results are logged as `hostname_ok` and `hostname_error`.

## Logs

- Default log file: `~/.config/urlmonitor/logs/monitor.log` (rotates at ~5 MB, keeps 3 backups).
- Formats:

  - `kv`: key=value pairs
  - `json`: structured JSON
  - `console`: colorful developer-friendly output

- Console output respects `--log-format`. File logs are always JSON regardless of console format.

Example (KV format, HTTPS):

```log
ts='2025-08-08T18:36:19.475234Z' level='info' event='https_check' url='https://httpbin.org/get' host='httpbin.org' port=443 via_proxy=False tls_ms=387 tls_protocol='TLSv1.2' tls_cipher='ECDHE-RSA-AES128-GCM-SHA256' http_status=200 http_status_line='HTTP/1.1 200 OK' tls_sni='httpbin.org' cert={'subject': 'CN=httpbin.org', 'issuer': 'C=US/O=Amazon/CN=Amazon RSA 2048 M03', 'serial_hex': '…', 'not_before': '20250720000000Z', 'not_after': '20260817235959Z', 'sans': ['DNS:httpbin.org', 'DNS:*.httpbin.org'], 'fingerprint_sha256': '…', 'hostname_to_verify': 'httpbin.org', 'hostname_ok': True, 'hostname_error': None}
```

## Tips

- For single-run checks, omit `--interval` (the monitor will exit after one request).
- For periodic monitoring, set `--interval` to your desired frequency.
- Use `--ca-bundle` when monitoring endpoints with private or custom CAs.
