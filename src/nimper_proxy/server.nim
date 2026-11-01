#
#          nimper-proxy — Multi-threaded HTTP & HTTPS (MITM CONNECT) Forward Proxy Server
#

import std/[net, nativesockets, strutils, httpcore, locks, json]
import nimper
import ./[config, certs]

type
  ParsedHttpRequest* = object
    httpMethod*: string
    rawTarget*: string
    httpVersion*: string
    headers*: seq[(string, string)]
    body*: string
    keepAlive*: bool

  ClientWorkerArgs = object
    clientFd: SocketHandle
    cfg: ProxyConfig

var logLock: Lock
initLock(logLock)

proc logInfo*(verbose: bool, msg: string) =
  if verbose:
    acquire(logLock)
    defer: release(logLock)
    echo "[nimper-proxy] ", msg

proc logError*(msg: string) =
  acquire(logLock)
  defer: release(logLock)
  stderr.writeLine("[nimper-proxy ERROR] " & msg)

proc httpStatusReason(code: int): string =
  case code
  of 100: "Continue"
  of 101: "Switching Protocols"
  of 200: "OK"
  of 201: "Created"
  of 202: "Accepted"
  of 204: "No Content"
  of 206: "Partial Content"
  of 301: "Moved Permanently"
  of 302: "Found"
  of 303: "See Other"
  of 304: "Not Modified"
  of 307: "Temporary Redirect"
  of 308: "Permanent Redirect"
  of 400: "Bad Request"
  of 401: "Unauthorized"
  of 403: "Forbidden"
  of 404: "Not Found"
  of 405: "Method Not Allowed"
  of 407: "Proxy Authentication Required"
  of 408: "Request Timeout"
  of 413: "Payload Too Large"
  of 429: "Too Many Requests"
  of 500: "Internal Server Error"
  of 502: "Bad Gateway"
  of 503: "Service Unavailable"
  of 504: "Gateway Timeout"
  else: "OK"

proc readExact(sock: net.Socket, length: int): string =
  result = newStringOfCap(length)
  var remaining = length
  while remaining > 0:
    let chunkSize = min(remaining, 16384)
    let chunk = sock.recv(chunkSize)
    if chunk.len == 0:
      break
    result.add(chunk)
    remaining -= chunk.len

proc readChunkedBody(sock: net.Socket): string =
  result = ""
  while true:
    let sizeLine = sock.recvLine()
    if sizeLine.len == 0:
      break
    var cleanSize = sizeLine.strip()
    let semi = cleanSize.find(';')
    if semi >= 0:
      cleanSize = cleanSize[0 ..< semi].strip()
    if cleanSize.len == 0:
      continue
    var chunkLen = 0
    try:
      chunkLen = parseHexInt(cleanSize)
    except ValueError:
      break
    if chunkLen == 0:
      # Read trailing headers until empty line
      while true:
        let trailer = sock.recvLine()
        if trailer == "\r\n" or trailer == "\n" or trailer == "":
          break
      break
    let data = readExact(sock, chunkLen)
    result.add(data)
    # Consume trailing CRLF after chunk data
    discard sock.recvLine()

proc readHttpRequest*(sock: net.Socket, parsed: var ParsedHttpRequest): bool =
  ## Reads a single HTTP/1.x request from `sock`. Returns false on EOF or closed socket.
  var reqLine = ""
  try:
    reqLine = sock.recvLine()
  except CatchableError:
    return false

  if reqLine.len == 0 or reqLine == "\r\n" or reqLine == "\n":
    return false

  let parts = reqLine.strip().splitWhitespace()
  if parts.len < 2:
    return false

  parsed.httpMethod = parts[0].toUpperAscii()
  parsed.rawTarget = parts[1]
  parsed.httpVersion = if parts.len >= 3: parts[2] else: "HTTP/1.1"
  parsed.headers = @[]
  parsed.body = ""
  parsed.keepAlive = parsed.httpVersion == "HTTP/1.1"

  var contentLength = 0
  var isChunked = false

  while true:
    let line = sock.recvLine()
    if line.len == 0 or line == "\r\n" or line == "\n":
      break
    let stripped = line.strip()
    let colon = stripped.find(':')
    if colon > 0:
      let k = stripped[0 ..< colon].strip()
      let v = stripped[colon + 1 .. ^1].strip()
      parsed.headers.add((k, v))
      let kl = k.toLowerAscii()
      if kl == "content-length":
        try:
          contentLength = parseInt(v)
        except ValueError:
          contentLength = 0
      elif kl == "transfer-encoding" and "chunked" in v.toLowerAscii():
        isChunked = true
      elif kl == "connection" or kl == "proxy-connection":
        if "close" in v.toLowerAscii():
          parsed.keepAlive = false
        elif "keep-alive" in v.toLowerAscii():
          parsed.keepAlive = true

  if parsed.httpMethod != "CONNECT":
    if isChunked:
      parsed.body = readChunkedBody(sock)
    elif contentLength > 0:
      parsed.body = readExact(sock, contentLength)

  return true

proc sendErrorResponse(sock: net.Socket, statusCode: int, message: string) =
  let reason = httpStatusReason(statusCode)
  let body = """{"error":""" & escapeJson(message) & ""","status":""" & $statusCode & "}\n"
  let resp = "HTTP/1.1 " & $statusCode & " " & reason & "\r\n" &
             "Content-Type: application/json; charset=utf-8\r\n" &
             "Content-Length: " & $body.len & "\r\n" &
             "Connection: close\r\n\r\n" & body
  try:
    sock.send(resp)
  except CatchableError:
    discard

proc findHostHeader(headers: openArray[(string, string)]): string =
  for (k, v) in headers:
    if cmpIgnoreCase(k, "host") == 0:
      return v.strip()
  return ""

proc buildTargetUrl*(req: ParsedHttpRequest, defaultScheme: string, connectAuthority: string = ""): string =
  ## Resolves the full target URL for `nimper` from a forward-proxy or MITM tunnel request.
  let raw = req.rawTarget.strip()
  if raw.startsWith("http://") or raw.startsWith("https://"):
    return raw

  var host = findHostHeader(req.headers)
  if host.len == 0:
    host = connectAuthority

  if host.len == 0:
    return ""

  # Omit default ports (:443 for https, :80 for http) for clean URLs
  if defaultScheme == "https" and host.endsWith(":443"):
    host = host[0 ..< host.len - 4]
  elif defaultScheme == "http" and host.endsWith(":80"):
    host = host[0 ..< host.len - 3]

  let pathPart = if raw.startsWith("/"): raw else: "/" & raw
  result = defaultScheme & "://" & host & pathPart

proc upstreamHttpVersionString(ver: int): string =
  case ver
  of ord(HTTP_VERSION_1_0): "HTTP/1.0"
  of ord(HTTP_VERSION_1_1): "HTTP/1.1"
  of ord(HTTP_VERSION_2_0), ord(HTTP_VERSION_2TLS), ord(HTTP_VERSION_2_PRIOR_KNOWLEDGE): "HTTP/2"
  of ord(HTTP_VERSION_3), ord(HTTP_VERSION_3ONLY): "HTTP/3"
  else: "unknown"

proc forwardViaNimper*(
  sock: net.Socket,
  httpReq: ParsedHttpRequest,
  targetUrl: string,
  baseCfg: ProxyConfig,
  connectOverrides: RequestOverrides = RequestOverrides(),
  keepAlive: bool = false
) =
  ## Executes `httpReq` against `targetUrl` using `nimper` and writes the HTTP/1.1 response back to `sock`.
  let mergedOverrides = extractOverridesFromHeaders(httpReq.headers, connectOverrides)
  let resolved = resolveRequestConfig(baseCfg, mergedOverrides)
  let forwardHeaders = filterUpstreamHeaders(httpReq.headers, resolved)

  logInfo(
    baseCfg.verbose,
    httpReq.httpMethod & " " & targetUrl &
    " [target=" & resolved.target &
    ", defaultHeaders=" & $resolved.defaultHeaders &
    ", followRedirects=" & $resolved.followRedirects & "]"
  )

  var nimperReq = initRequest(
    url = targetUrl,
    httpMethod = httpReq.httpMethod,
    target = resolved.target,
    defaultHeaders = resolved.defaultHeaders,
    headers = forwardHeaders,
    body = httpReq.body,
    timeoutMs = resolved.timeoutMs,
    connectTimeoutMs = resolved.connectTimeoutMs,
    followRedirects = resolved.followRedirects,
    safeRedirects = resolved.safeRedirects,
    maxRedirects = resolved.maxRedirects,
    verifySsl = resolved.verifySsl,
    proxy = resolved.upstreamProxy,
    httpVersion = resolved.httpVersion
  )

  var resp: Response
  try:
    resp = perform(nimperReq)
  except CurlImpersonateError as e:
    logError("nimper error for " & targetUrl & ": " & e.msg)
    sendErrorResponse(sock, 502, "Bad Gateway (nimper): " & e.msg)
    return
  except CatchableError as e:
    logError("unexpected error for " & targetUrl & ": " & e.msg)
    sendErrorResponse(sock, 500, "Internal Proxy Error: " & e.msg)
    return

  let statusCode = if resp.statusCode > 0: resp.statusCode else: 200
  let reason = httpStatusReason(statusCode)

  var outBuf = newStringOfCap(512 + resp.body.len)
  outBuf.add("HTTP/1.1 " & $statusCode & " " & reason & "\r\n")

  if resp.headers != nil:
    for k, v in resp.headers.pairs:
      let kl = k.toLowerAscii()
      # Skip framing & hop-by-hop headers because libcurl-impersonate already decompressed and unchunked the body
      if kl in ["transfer-encoding", "content-encoding", "content-length", "connection", "proxy-connection", "keep-alive"]:
        continue
      outBuf.add(k & ": " & v & "\r\n")

  outBuf.add("X-Nimper-Target: " & resolved.target & "\r\n")
  if resp.url.len > 0:
    outBuf.add("X-Nimper-Effective-Url: " & resp.url & "\r\n")
  outBuf.add("X-Nimper-Upstream-Protocol: " & upstreamHttpVersionString(resp.httpVersion) & "\r\n")
  if resp.redirectCount > 0:
    outBuf.add("X-Nimper-Redirect-Count: " & $resp.redirectCount & "\r\n")

  outBuf.add("Content-Length: " & $resp.body.len & "\r\n")
  outBuf.add("Connection: " & (if keepAlive: "keep-alive" else: "close") & "\r\n")
  outBuf.add("\r\n")

  if httpReq.httpMethod != "HEAD" and resp.body.len > 0:
    outBuf.add(resp.body)

  sock.send(outBuf)

proc parseConnectAuthority*(rawTarget: string): (string, int) =
  ## Parses `host:port` (including IPv6 `[::1]:443`) from a `CONNECT` request target.
  let clean = rawTarget.strip()
  if clean.startsWith("["):
    let closeBracket = clean.find(']')
    if closeBracket > 0:
      let host = clean[1 ..< closeBracket]
      var port = 443
      if closeBracket + 1 < clean.len and clean[closeBracket + 1] == ':':
        try:
          port = parseInt(clean[closeBracket + 2 .. ^1])
        except ValueError:
          port = 443
      return (host, port)
  let lastColon = clean.rfind(':')
  if lastColon > 0:
    let host = clean[0 ..< lastColon]
    var port = 443
    try:
      port = parseInt(clean[lastColon + 1 .. ^1])
    except ValueError:
      port = 443
    return (host, port)
  return (clean, 443)

proc handleConnectMitm(client: net.Socket, connectReq: ParsedHttpRequest, cfg: ProxyConfig) =
  let (host, port) = parseConnectAuthority(connectReq.rawTarget)
  if host.len == 0:
    sendErrorResponse(client, 400, "Invalid CONNECT authority")
    return

  let connectOverrides = extractOverridesFromHeaders(connectReq.headers)
  logInfo(cfg.verbose, "CONNECT " & host & ":" & $port & " (MITM TLS termination)")

  var certPair: CertPair
  try:
    certPair = getOrCreateHostCert(cfg.caDir, host)
  except CatchableError as e:
    logError("Failed to generate MITM certificate for " & host & ": " & e.msg)
    sendErrorResponse(client, 502, "Failed to generate MITM certificate: " & e.msg)
    return

  # Acknowledge the CONNECT tunnel
  client.send("HTTP/1.1 200 Connection Established\r\nProxy-Agent: nimper-proxy\r\n\r\n")

  var sslCtx: SslContext = nil
  try:
    sslCtx = createServerSslContext(certPair)
    wrapConnectedSocket(sslCtx, client, handshakeAsServer, host)
  except CatchableError as e:
    logError("TLS handshake with client failed for " & host & ": " & e.msg)
    if sslCtx != nil:
      try: sslCtx.destroyContext() except CatchableError: discard
    return

  defer:
    if sslCtx != nil:
      try: sslCtx.destroyContext() except CatchableError: discard

  let authority = if port == 443: host else: host & ":" & $port

  # Serve one or more decrypted HTTP/1.1 requests inside the TLS tunnel
  while true:
    var innerReq: ParsedHttpRequest
    if not readHttpRequest(client, innerReq):
      break
    let targetUrl = buildTargetUrl(innerReq, "https", authority)
    if targetUrl.len == 0:
      sendErrorResponse(client, 400, "Missing Host header in tunneled request")
      break
    try:
      forwardViaNimper(
        client,
        innerReq,
        targetUrl,
        cfg,
        connectOverrides = connectOverrides,
        keepAlive = innerReq.keepAlive
      )
    except CatchableError:
      break
    if not innerReq.keepAlive:
      break

proc handleClientSocket(client: net.Socket, cfg: ProxyConfig) =
  while true:
    var req: ParsedHttpRequest
    if not readHttpRequest(client, req):
      break

    if req.httpMethod == "CONNECT":
      handleConnectMitm(client, req, cfg)
      break

    # Built-in proxy health/status endpoint when accessed directly
    if req.rawTarget == "/__nimper_proxy/status":
      let body = """{"status":"ok","defaultTarget":"""" & cfg.target & """","impersonateBuild":""" & $isImpersonateBuild() & "}\n"
      let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " & $body.len & "\r\nConnection: close\r\n\r\n" & body
      client.send(resp)
      break

    let targetUrl = buildTargetUrl(req, "http")
    if targetUrl.len == 0:
      sendErrorResponse(client, 400, "Missing target URL or Host header")
      break

    try:
      forwardViaNimper(
        client,
        req,
        targetUrl,
        cfg,
        keepAlive = req.keepAlive
      )
    except CatchableError:
      break

    if not req.keepAlive:
      break

proc clientWorkerProc(args: ClientWorkerArgs) {.thread.} =
  {.cast(gcsafe).}:
    let client = newSocket(args.clientFd)
    try:
      handleClientSocket(client, args.cfg)
    except CatchableError as e:
      if args.cfg.verbose:
        logError("Worker exception: " & e.msg)
    finally:
      try:
        client.close()
      except CatchableError:
        discard

proc runProxyServer*(cfg: ProxyConfig) =
  ## Initializes `nimper` and the MITM Root CA, binds to `cfg.bindAddr:cfg.port`,
  ## and dispatches incoming proxy connections to worker threads.
  ensureGlobalInit()
  discard ensureRootCa(cfg.caDir)

  var server = newSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(cfg.port), cfg.bindAddr)
  server.listen()

  while true:
    var client: net.Socket = nil
    try:
      server.accept(client)
    except CatchableError:
      continue

    if client == nil:
      continue

    let fd = client.getFd()
    # Detach ownership from `client` ref in main thread so GC doesn't close `fd` while worker thread uses it
    GC_ref(client)
    var workerPtr = cast[ptr Thread[ClientWorkerArgs]](allocShared0(sizeof(Thread[ClientWorkerArgs])))
    try:
      createThread(workerPtr[], clientWorkerProc, ClientWorkerArgs(clientFd: fd, cfg: cfg))
    except CatchableError as e:
      logError("Failed to spawn worker thread: " & e.msg)
      deallocShared(workerPtr)
      try: client.close() except CatchableError: discard
