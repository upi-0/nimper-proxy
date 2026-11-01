# `nimper-proxy` — Browser-Impersonating HTTP & HTTPS Forward Proxy

A multi-threaded HTTP & HTTPS (MITM `CONNECT`) forward proxy written in Nim powered by [`nimper`](../agy/src) (`libcurl-impersonate`).

Any HTTP/HTTPS client (`curl -x`, Python `requests`, browsers, scrapers) routed through `nimper-proxy` automatically inherits authentic browser TLS (BoringSSL), HTTP/2, and HTTP/3 fingerprints (`chrome152`, `firefox155`, `safari270`, `edge101`, `tor145`, etc.).

---

## Build

`config.nims` is preconfigured with `--path:"../agy/src"`, `--threads:on`, and `--define:ssl`:

```bash
nim c -d:release -o:nimper-proxy src/nimper_proxy.nim
```

---

## Usage

```bash
# Start proxy on 127.0.0.1:8080 with default Firefox 155 impersonation
./nimper-proxy --bind 127.0.0.1 --port 8080

# List all 47+ supported browser targets
./nimper-proxy --list-targets
```

### Example `curl` Requests

```bash
# 1. HTTPS request via CONNECT (MITM TLS terminated locally, forwarded via nimper)
curl -k -x http://127.0.0.1:8080 https://tls.browserleaks.com/json

# 2. Trust the generated Root CA to omit -k:
curl --cacert ~/.cache/nimper-proxy/certs/ca.crt -x http://127.0.0.1:8080 https://tls.browserleaks.com/json

# 3. Override browser profile per-request via header:
curl -k -x http://127.0.0.1:8080 -H "X-Impersonate: firefox155" https://tls.browserleaks.com/json
curl -k -x http://127.0.0.1:8080 -H "X-Impersonate: safari270" https://tls.browserleaks.com/json

# 4. Override via CONNECT --proxy-header:
curl -k -x http://127.0.0.1:8080 --proxy-header "X-Impersonate: tor145" https://tls.browserleaks.com/json
```

### Supported Per-Request Header Overrides

| Header | Description |
|--------|-------------|
| `X-Impersonate` / `X-Nimper-Target` | Browser profile (`chrome152`, `firefox155`, `safari270`, `edge101`, `tor145`, etc.) |
| `X-Default-Headers` | Inject browser default HTTP headers (`true` / `false`) |
| `X-Follow-Redirects` | Follow upstream 3xx redirects inside `nimper` (`true` / `false`) |
| `X-Safe-Redirects` | Enable `CURLFOLLOW_SAFE` SSRF protection on redirects (`true` / `false`) |
| `X-Verify-Ssl` | Verify upstream TLS certificates (`true` / `false`) |
| `X-Proxy` | Chain through an upstream HTTP/SOCKS5 proxy (`socks5://127.0.0.1:9050`) |
| `X-Timeout-Ms` | Request timeout in milliseconds |
| `X-Http-Version` | Force upstream HTTP version (`1.1`, `2`, `3`, `3only`) |
| `X-Preserve-User-Agent` | Keep the client's `User-Agent` header (`true` / `false`) |

---

## Running Tests

```bash
nim c -r tests/test_proxy.nim
```
