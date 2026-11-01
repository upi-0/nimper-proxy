#
#          nimper-proxy — Configuration & Per-Request Header Overrides
#

import std/[os, parseopt, strutils]
import nimper

type
  ProxyConfig* = object
    bindAddr*: string
    port*: int
    target*: string
    defaultHeaders*: bool
    followRedirects*: bool
    safeRedirects*: bool
    maxRedirects*: int
    verifySsl*: bool
    upstreamProxy*: string
    timeoutMs*: int
    connectTimeoutMs*: int
    caDir*: string
    verbose*: bool
    listTargets*: bool
    showHelp*: bool

  RequestOverrides* = object
    hasTarget*: bool
    target*: string
    hasDefaultHeaders*: bool
    defaultHeaders*: bool
    hasFollowRedirects*: bool
    followRedirects*: bool
    hasSafeRedirects*: bool
    safeRedirects*: bool
    hasVerifySsl*: bool
    verifySsl*: bool
    hasUpstreamProxy*: bool
    upstreamProxy*: string
    hasTimeoutMs*: bool
    timeoutMs*: int
    hasHttpVersion*: bool
    httpVersion*: abi.HTTP_VERSION
    preserveUserAgent*: bool

  ResolvedRequestConfig* = object
    target*: string
    defaultHeaders*: bool
    followRedirects*: bool
    safeRedirects*: bool
    maxRedirects*: int
    verifySsl*: bool
    upstreamProxy*: string
    timeoutMs*: int
    connectTimeoutMs*: int
    httpVersion*: abi.HTTP_VERSION
    preserveUserAgent*: bool

proc parseBoolFlag*(val: string, defaultVal: bool = false): bool =
  let clean = val.strip().toLowerAscii()
  case clean
  of "1", "true", "yes", "on", "y":
    return true
  of "0", "false", "no", "off", "n":
    return false
  else:
    return defaultVal

proc parseHttpVersionHeader*(val: string): abi.HTTP_VERSION =
  let clean = val.strip().toLowerAscii()
  case clean
  of "1.0", "http/1.0":
    return HTTP_VERSION_1_0
  of "1.1", "http/1.1", "1":
    return HTTP_VERSION_1_1
  of "2", "2.0", "h2", "http/2":
    return HTTP_VERSION_2_0
  of "2tls", "h2tls":
    return HTTP_VERSION_2TLS
  of "3", "3.0", "h3", "http/3":
    return HTTP_VERSION_3
  of "3only", "h3only":
    return HTTP_VERSION_3ONLY
  else:
    return HTTP_VERSION_NONE

proc initDefaultProxyConfig*(): ProxyConfig =
  result.bindAddr = getEnv("NIMPER_BIND", "127.0.0.1")
  try:
    result.port = parseInt(getEnv("NIMPER_PORT", "8080"))
  except ValueError:
    result.port = 8080
  result.target = getEnv("NIMPER_TARGET", $itFirefox155)
  result.defaultHeaders = parseBoolFlag(getEnv("NIMPER_DEFAULT_HEADERS", "true"), true)
  result.followRedirects = parseBoolFlag(getEnv("NIMPER_FOLLOW_REDIRECTS", "false"), false)
  result.safeRedirects = parseBoolFlag(getEnv("NIMPER_SAFE_REDIRECTS", "false"), false)
  result.maxRedirects = 30
  result.verifySsl = parseBoolFlag(getEnv("NIMPER_VERIFY_SSL", "true"), true)
  result.upstreamProxy = getEnv("NIMPER_UPSTREAM_PROXY", "")
  try:
    result.timeoutMs = parseInt(getEnv("NIMPER_TIMEOUT_MS", "30000"))
  except ValueError:
    result.timeoutMs = 30_000
  try:
    result.connectTimeoutMs = parseInt(getEnv("NIMPER_CONNECT_TIMEOUT_MS", "10000"))
  except ValueError:
    result.connectTimeoutMs = 10_000
  result.caDir = getEnv("NIMPER_CA_DIR", getHomeDir() / ".cache" / "nimper-proxy" / "certs")
  result.verbose = parseBoolFlag(getEnv("NIMPER_VERBOSE", "false"), false)

proc parseCliConfig*(args: seq[string] = commandLineParams()): ProxyConfig =
  result = initDefaultProxyConfig()
  var p = initOptParser(args)
  while true:
    p.next()
    case p.kind
    of cmdEnd:
      break
    of cmdShortOption, cmdLongOption:
      let key = p.key.toLowerAscii().replace("_", "-")
      case key
      of "b", "bind", "host":
        result.bindAddr = p.val
      of "p", "port":
        result.port = parseInt(p.val)
      of "t", "target", "impersonate":
        result.target = p.val
      of "default-headers":
        result.defaultHeaders = if p.val.len == 0: true else: parseBoolFlag(p.val, true)
      of "no-default-headers":
        result.defaultHeaders = false
      of "follow-redirects", "location", "l":
        result.followRedirects = if p.val.len == 0: true else: parseBoolFlag(p.val, true)
      of "safe-redirects":
        result.safeRedirects = if p.val.len == 0: true else: parseBoolFlag(p.val, true)
      of "max-redirects":
        result.maxRedirects = parseInt(p.val)
      of "verify-ssl":
        result.verifySsl = if p.val.len == 0: true else: parseBoolFlag(p.val, true)
      of "k", "insecure", "no-verify-ssl":
        result.verifySsl = false
      of "x", "upstream-proxy", "proxy":
        result.upstreamProxy = p.val
      of "timeout", "timeout-ms":
        result.timeoutMs = parseInt(p.val)
      of "connect-timeout", "connect-timeout-ms":
        result.connectTimeoutMs = parseInt(p.val)
      of "ca-dir":
        result.caDir = p.val
      of "v", "verbose":
        result.verbose = if p.val.len == 0: true else: parseBoolFlag(p.val, true)
      of "list-targets":
        result.listTargets = true
      of "h", "help":
        result.showHelp = true
      else:
        discard
    of cmdArgument:
      discard

proc isHopByHopOrControlHeader*(keyLower: string): bool =
  ## Returns true if the header is a hop-by-hop proxy header or a `nimper-proxy` control header.
  case keyLower
  of "proxy-connection", "connection", "keep-alive", "transfer-encoding",
     "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization",
     "x-impersonate", "x-nimper-target",
     "x-default-headers", "x-nimper-default-headers",
     "x-proxy", "x-nimper-proxy",
     "x-follow-redirects", "x-nimper-follow-redirects",
     "x-safe-redirects", "x-nimper-safe-redirects",
     "x-verify-ssl", "x-nimper-verify-ssl",
     "x-timeout-ms", "x-nimper-timeout-ms",
     "x-http-version", "x-nimper-http-version",
     "x-preserve-user-agent", "x-nimper-preserve-user-agent":
    return true
  else:
    return false

proc extractOverridesFromHeaders*(
  rawHeaders: openArray[(string, string)],
  existing: RequestOverrides = RequestOverrides()
): RequestOverrides =
  ## Inspects request headers for `X-Impersonate*` / `X-Nimper-*` overrides and merges them on top of `existing`.
  result = existing
  for (k, v) in rawHeaders:
    let kl = k.strip().toLowerAscii()
    let val = v.strip()
    case kl
    of "x-impersonate", "x-nimper-target":
      if val.len > 0:
        result.hasTarget = true
        result.target = val
    of "x-default-headers", "x-nimper-default-headers":
      result.hasDefaultHeaders = true
      result.defaultHeaders = parseBoolFlag(val, true)
    of "x-follow-redirects", "x-nimper-follow-redirects":
      result.hasFollowRedirects = true
      result.followRedirects = parseBoolFlag(val, false)
    of "x-safe-redirects", "x-nimper-safe-redirects":
      result.hasSafeRedirects = true
      result.safeRedirects = parseBoolFlag(val, false)
    of "x-verify-ssl", "x-nimper-verify-ssl":
      result.hasVerifySsl = true
      result.verifySsl = parseBoolFlag(val, true)
    of "x-proxy", "x-nimper-proxy":
      result.hasUpstreamProxy = true
      result.upstreamProxy = val
    of "x-timeout-ms", "x-nimper-timeout-ms":
      try:
        result.timeoutMs = parseInt(val)
        result.hasTimeoutMs = true
      except ValueError:
        discard
    of "x-http-version", "x-nimper-http-version":
      let hv = parseHttpVersionHeader(val)
      if hv != HTTP_VERSION_NONE:
        result.hasHttpVersion = true
        result.httpVersion = hv
    of "x-preserve-user-agent", "x-nimper-preserve-user-agent":
      result.preserveUserAgent = parseBoolFlag(val, false)
    else:
      discard

proc resolveRequestConfig*(base: ProxyConfig, ov: RequestOverrides): ResolvedRequestConfig =
  result.target = if ov.hasTarget: ov.target else: base.target
  result.defaultHeaders = if ov.hasDefaultHeaders: ov.defaultHeaders else: base.defaultHeaders
  result.followRedirects = if ov.hasFollowRedirects: ov.followRedirects else: base.followRedirects
  result.safeRedirects = if ov.hasSafeRedirects: ov.safeRedirects else: base.safeRedirects
  result.maxRedirects = base.maxRedirects
  result.verifySsl = if ov.hasVerifySsl: ov.verifySsl else: base.verifySsl
  result.upstreamProxy = if ov.hasUpstreamProxy: ov.upstreamProxy else: base.upstreamProxy
  result.timeoutMs = if ov.hasTimeoutMs: ov.timeoutMs else: base.timeoutMs
  result.connectTimeoutMs = base.connectTimeoutMs
  result.httpVersion = if ov.hasHttpVersion: ov.httpVersion else: HTTP_VERSION_NONE
  result.preserveUserAgent = ov.preserveUserAgent

proc filterUpstreamHeaders*(
  rawHeaders: openArray[(string, string)],
  resolved: ResolvedRequestConfig
): seq[(string, string)] =
  ## Filters client headers before passing them to `nimper`:
  ## - Strips hop-by-hop and `X-Impersonate*`/`X-Nimper-*` control headers
  ## - Strips `Host` (since `libcurl` generates `Host` / `:authority` from the URL)
  ## - Strips `Accept-Encoding` (since `nimper` advertises and auto-decompresses `gzip, deflate, br, zstd`)
  ## - Strips `User-Agent` when `defaultHeaders = true` and `preserveUserAgent = false` so that
  ##   `libcurl-impersonate`'s authentic browser `User-Agent` is sent instead of `curl/8.x`
  result = @[]
  for (k, v) in rawHeaders:
    let kl = k.strip().toLowerAscii()
    if isHopByHopOrControlHeader(kl):
      continue
    if kl == "host" or kl == "accept-encoding" or kl == "content-length":
      continue
    if kl == "user-agent" and resolved.defaultHeaders and not resolved.preserveUserAgent:
      continue
    result.add((k.strip(), v.strip()))

proc formatHelpText*(): string =
  result = """
nimper-proxy — HTTP & HTTPS (MITM CONNECT) Forward Proxy powered by nimper (libcurl-impersonate)

Usage:
  nimper_proxy [options]

Options:
  -b, --bind <addr>            Bind address (default: 127.0.0.1, env: NIMPER_BIND)
  -p, --port <port>            Listen port (default: 8080, env: NIMPER_PORT)
  -t, --target <profile>       Default browser target (default: firefox155, env: NIMPER_TARGET)
      --default-headers <bool> Inject default browser headers (default: true)
      --no-default-headers     Disable default browser headers
  -l, --follow-redirects       Follow upstream 3xx redirects automatically inside nimper
      --safe-redirects         Block redirects to private/loopback IPs (CURLFOLLOW_SAFE)
  -k, --insecure               Disable upstream SSL certificate verification
  -x, --upstream-proxy <url>   Chain requests through an upstream HTTP/SOCKS5 proxy
      --timeout <ms>           Request timeout in ms (default: 30000)
      --connect-timeout <ms>   Connect timeout in ms (default: 10000)
      --ca-dir <dir>           MITM Root CA & leaf cert cache directory
      --list-targets           List all supported browser impersonation targets and exit
  -v, --verbose                Enable verbose request/response logging
  -h, --help                   Show this help message

Per-Request Header Overrides (sent as request or --proxy-header):
  X-Impersonate: <target>      Override browser target (e.g., firefox155, safari270, chrome152_macos, tor145)
  X-Default-Headers: <bool>    Toggle default browser headers (true/false)
  X-Follow-Redirects: <bool>   Toggle redirect following (true/false)
  X-Safe-Redirects: <bool>     Toggle SSRF-safe redirects (true/false)
  X-Verify-Ssl: <bool>         Toggle upstream SSL verification (true/false)
  X-Proxy: <url>               Per-request upstream proxy (e.g., socks5://127.0.0.1:9050)
  X-Timeout-Ms: <ms>           Per-request timeout in ms
  X-Http-Version: <ver>        Force HTTP version (1.1, 2, 3, 3only)
  X-Preserve-User-Agent: true  Keep the client's User-Agent instead of browser default
"""

proc formatTargetsTable*(): string =
  result = "Supported Browser Impersonation Targets (nimper / libcurl-impersonate):\n"
  result.add(alignLeft("Target", 22) & alignLeft("Alias", 18) & alignLeft("Family", 10) &
             alignLeft("Version", 10) & alignLeft("HTTP/3 FP", 11) & "OS\n")
  result.add(repeat('-', 85) & "\n")
  for t in ImpersonateTarget:
    if t == itNone:
      continue
    let ti = t.info()
    let h3 = if ti.supportsHttp3Fingerprint: "yes" else: "no"
    result.add(
      alignLeft(ti.name, 22) &
      alignLeft(ti.alias, 18) &
      alignLeft($ti.family, 10) &
      alignLeft(ti.version, 10) &
      alignLeft(h3, 11) &
      ti.os & "\n"
    )
  result.add("\nShort family aliases: chrome, chrome_macos, chrome_android, firefox (ff), safari, safari_ios, edge, tor\n")
