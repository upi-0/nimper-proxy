#
#          nimper-proxy — Multi-threaded HTTP & HTTPS (MITM CONNECT) Forward Proxy Server
#

import std/[net, nativesockets, strutils, httpcore, locks, json, os]
when defined(windows):
  import std/winlean
else:
  import std/posix
import nimper
import ./[config, certs]

const
  MaxSocketQueueCapacity = 4096
  StreamBufferSize = 65536

type
  ParsedHttpRequest* = object
    httpMethod*: string
    rawTarget*: string
    httpVersion*: string
    headers*: seq[(string, string)]
    body*: string
    keepAlive*: bool

  SocketQueue = object
    lock: Lock
    notEmpty: Cond
    notFull: Cond
    buf: array[MaxSocketQueueCapacity, SocketHandle]
    head: int
    tail: int
    count: int

  WorkerThreadArgs = object
    workerId: int
    cfg: ProxyConfig
    queue: ptr SocketQueue
    shareHandle: PSH

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

proc httpStatusReason*(code: int): string =
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
  of 412: "Precondition Failed"
  of 413: "Payload Too Large"
  of 414: "URI Too Long"
  of 415: "Unsupported Media Type"
  of 416: "Range Not Satisfiable"
  of 422: "Unprocessable Entity"
  of 429: "Too Many Requests"
  of 500: "Internal Server Error"
  of 502: "Bad Gateway"
  of 503: "Service Unavailable"
  of 504: "Gateway Timeout"
  else: "OK"

proc toHexLower(n: int): string =
  const digits = "0123456789abcdef"
  if n <= 0:
    return "0"
  var val = n
  var tmp = ""
  while val > 0:
    tmp.add(digits[val and 0xF])
    val = val shr 4
  result = newString(tmp.len)
  for i in 0 ..< tmp.len:
    result[i] = tmp[tmp.len - 1 - i]

proc isClientDisconnected*(sock: net.Socket): bool =
  ## Non-blocking check whether the downstream client closed or reset the TCP connection.
  ## Uses `selectRead(0)` + `recv(..., MSG_PEEK)` so pipelined requests are never consumed.
  let fd = sock.getFd()
  if fd == osInvalidSocket:
    return true
  var readFds = @[fd]
  try:
    if selectRead(readFds, 0) > 0:
      var dummy: char = '\0'
      when defined(windows):
        let n = winlean.recv(fd, addr dummy, 1, MSG_PEEK)
        if n == 0:
          return true
        elif n < 0:
          let err = osLastError().int32
          if err != WSAEWOULDBLOCK and err != WSAEINTR:
            return true
      else:
        let n = posix.recv(fd, addr dummy, 1, posix.MSG_PEEK)
        if n == 0:
          return true
        elif n < 0:
          let err = osLastError().int32
          if err != EWOULDBLOCK and err != EAGAIN and err != EINTR:
            return true
  except CatchableError:
    return true
  return false

proc sendAll*(sock: net.Socket, data: pointer, totalLen: int): bool =
  ## Writes `totalLen` raw bytes from `data` to `sock` without heap copies or busy-spinning.
  ## Returns `false` immediately if the client disconnects.
  if totalLen <= 0:
    return true
  let fd = sock.getFd()
  if fd == osInvalidSocket:
    return false
  let baseAddr = cast[uint](data)
  var written = 0
  var waitSlices = 0
  const maxWaitSlices = 240 # 240 * 250ms = 60s max downstream ZeroWindow backpressure stall

  while written < totalLen:
    let chunkPtr = cast[pointer](baseAddr + uint(written))
    let remaining = totalLen - written
    var sent = 0
    try:
      sent = sock.send(chunkPtr, remaining)
    except CatchableError:
      return false

    if sent > 0:
      written += sent
      waitSlices = 0
    elif sent == 0:
      return false
    else:
      let err = osLastError().int32
      when defined(windows):
        let isWouldBlock = (err == WSAEWOULDBLOCK or err == WSAEINTR)
      else:
        let isWouldBlock = (err == EWOULDBLOCK or err == EAGAIN or err == EINTR)
      if not isWouldBlock:
        return false
      if isClientDisconnected(sock):
        return false
      inc(waitSlices)
      if waitSlices > maxWaitSlices:
        return false
      var writeFds = @[fd]
      try:
        discard selectWrite(writeFds, 250)
      except CatchableError:
        return false
      if isClientDisconnected(sock):
        return false
  return true

proc sendString(sock: net.Socket, s: string): bool {.inline.} =
  if s.len == 0:
    return true
  sendAll(sock, unsafeAddr s[0], s.len)

proc readExact(sock: net.Socket, length: int): string =
  if length <= 0:
    return ""
  result = newString(length)
  var totalRead = 0
  while totalRead < length:
    let got = sock.recv(addr result[totalRead], length - totalRead)
    if got <= 0:
      result.setLen(totalRead)
      break
    totalRead += got

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
  ## Reads a single HTTP/1.x request from buffered `sock`. Returns false on EOF or closed socket.
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
  discard sendString(sock, resp)

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
  keepAlive: bool = false,
  session: ImpersonateSession = nil,
  shareHandle: PSH = nil
): bool =
  ## Streams `httpReq` against `targetUrl` using `nimper` directly to `sock` without buffering
  ## the full response body in memory. Returns `true` if the client connection can be kept alive.
  let mergedOverrides = extractOverridesFromHeaders(httpReq.headers, connectOverrides)
  let resolved = resolveRequestConfig(baseCfg, mergedOverrides)
  let forwardHeaders = filterUpstreamHeaders(httpReq.headers, resolved)
  let isRange = hasRangeHeader(httpReq.headers)
  let stallSec = max(10, resolved.timeoutMs div 1000)

  logInfo(
    baseCfg.verbose,
    httpReq.httpMethod & " " & targetUrl &
    " [target=" & resolved.target &
    ", range=" & $isRange &
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
    timeoutMs = 0, # Use stall detection (lowSpeedLimit/lowSpeedTimeSec) instead of hard total duration timeout
    connectTimeoutMs = resolved.connectTimeoutMs,
    lowSpeedLimit = 1,
    lowSpeedTimeSec = stallSec,
    bufferSize = StreamBufferSize,
    httpContentDecoding = not isRange,
    followRedirects = resolved.followRedirects,
    safeRedirects = resolved.safeRedirects,
    maxRedirects = resolved.maxRedirects,
    verifySsl = resolved.verifySsl,
    proxy = resolved.upstreamProxy,
    httpVersion = resolved.httpVersion,
    share = shareHandle
  )
  if isRange:
    nimperReq.acceptEncoding = "identity"

  var headersSentToClient = false
  var useChunkedFraming = false
  var noBodyResponse = false

  let onHeadersCb = proc(head: StreamResponseHead): bool {.gcsafe.} =
    if isClientDisconnected(sock):
      return false

    let statusCode = if head.statusCode > 0: head.statusCode else: 200
    let reason = httpStatusReason(statusCode)
    noBodyResponse =
      (httpReq.httpMethod == "HEAD") or
      (statusCode in [101, 204, 304]) or
      (statusCode >= 100 and statusCode < 200)

    var upstreamContentLen = ""
    var upstreamContentEnc = ""
    if head.headers != nil:
      for k, v in head.headers.pairs:
        let kl = k.toLowerAscii()
        if kl == "content-length" and upstreamContentLen.len == 0:
          upstreamContentLen = v.strip()
        elif kl == "content-encoding" and upstreamContentEnc.len == 0:
          upstreamContentEnc = v.strip()

    let isDecodedOnTheFly =
      nimperReq.httpContentDecoding and
      upstreamContentEnc.len > 0 and
      cmpIgnoreCase(upstreamContentEnc, "identity") != 0

    if noBodyResponse:
      useChunkedFraming = false
    elif upstreamContentLen.len > 0 and not isDecodedOnTheFly:
      useChunkedFraming = false
    else:
      useChunkedFraming = true

    var headerBuf = newStringOfCap(512)
    headerBuf.add("HTTP/1.1 " & $statusCode & " " & reason & "\r\n")

    if head.headers != nil:
      for k, v in head.headers.pairs:
        let kl = k.toLowerAscii()
        if kl in ["transfer-encoding", "content-length", "connection", "proxy-connection", "keep-alive"]:
          continue
        if kl == "content-encoding" and nimperReq.httpContentDecoding:
          continue
        headerBuf.add(k & ": " & v & "\r\n")

    headerBuf.add("X-Nimper-Target: " & resolved.target & "\r\n")
    if head.url.len > 0:
      headerBuf.add("X-Nimper-Effective-Url: " & head.url & "\r\n")
    headerBuf.add("X-Nimper-Upstream-Protocol: " & upstreamHttpVersionString(head.httpVersion) & "\r\n")
    if head.redirectCount > 0:
      headerBuf.add("X-Nimper-Redirect-Count: " & $head.redirectCount & "\r\n")

    if noBodyResponse:
      if upstreamContentLen.len > 0 and not isDecodedOnTheFly:
        headerBuf.add("Content-Length: " & upstreamContentLen & "\r\n")
    elif useChunkedFraming:
      headerBuf.add("Transfer-Encoding: chunked\r\n")
    else:
      headerBuf.add("Content-Length: " & upstreamContentLen & "\r\n")

    headerBuf.add("Connection: " & (if keepAlive: "keep-alive" else: "close") & "\r\n")
    headerBuf.add("\r\n")

    if not sendString(sock, headerBuf):
      return false
    headersSentToClient = true
    return true

  let onChunkCb = proc(data: pointer, len: int): bool {.gcsafe.} =
    if noBodyResponse or len <= 0:
      return true
    if useChunkedFraming:
      let prefix = toHexLower(len) & "\r\n"
      if not sendString(sock, prefix):
        return false
      if not sendAll(sock, data, len):
        return false
      if not sendString(sock, "\r\n"):
        return false
      return true
    else:
      return sendAll(sock, data, len)

  let onProgressCb = proc(dlTotal, dlNow, ulTotal, ulNow: int64): bool {.gcsafe.} =
    return not isClientDisconnected(sock)

  var resp: Response
  try:
    if session != nil:
      resp = session.requestStreaming(nimperReq, onHeadersCb, onChunkCb, onProgressCb)
    else:
      resp = performStreaming(nimperReq, onHeadersCb, onChunkCb, onProgressCb)
  except CurlImpersonateError as e:
    if not headersSentToClient:
      logError("nimper error for " & targetUrl & ": " & e.msg)
      sendErrorResponse(sock, 502, "Bad Gateway (nimper): " & e.msg)
    return false
  except CatchableError as e:
    if not headersSentToClient:
      logError("unexpected error for " & targetUrl & ": " & e.msg)
      sendErrorResponse(sock, 500, "Internal Proxy Error: " & e.msg)
    return false

  if resp.abortedByCallback:
    logInfo(baseCfg.verbose, "Client disconnected mid-stream; aborted upstream download for " & targetUrl)
    return false

  if useChunkedFraming and headersSentToClient and not noBodyResponse:
    if not sendString(sock, "0\r\n\r\n"):
      return false

  return keepAlive

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

proc handleConnectMitm(
  client: net.Socket,
  connectReq: ParsedHttpRequest,
  cfg: ProxyConfig,
  session: ImpersonateSession,
  shareHandle: PSH
) =
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
  if not sendString(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: nimper-proxy\r\n\r\n"):
    return

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
    var canKeepAlive = false
    try:
      canKeepAlive = forwardViaNimper(
        client,
        innerReq,
        targetUrl,
        cfg,
        connectOverrides = connectOverrides,
        keepAlive = innerReq.keepAlive,
        session = session,
        shareHandle = shareHandle
      )
    except CatchableError:
      break
    if not canKeepAlive or not innerReq.keepAlive:
      break

proc handleClientSocket(
  client: net.Socket,
  cfg: ProxyConfig,
  session: ImpersonateSession,
  shareHandle: PSH
) =
  while true:
    var req: ParsedHttpRequest
    if not readHttpRequest(client, req):
      break

    if req.httpMethod == "CONNECT":
      handleConnectMitm(client, req, cfg, session, shareHandle)
      break

    # Built-in proxy health/status endpoint when accessed directly
    if req.rawTarget == "/__nimper_proxy/status":
      let body = """{"status":"ok","defaultTarget":"""" & cfg.target & """","impersonateBuild":""" & $isImpersonateBuild() & "}\n"
      let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " & $body.len & "\r\nConnection: close\r\n\r\n" & body
      discard sendString(client, resp)
      break

    let targetUrl = buildTargetUrl(req, "http")
    if targetUrl.len == 0:
      sendErrorResponse(client, 400, "Missing target URL or Host header")
      break

    var canKeepAlive = false
    try:
      canKeepAlive = forwardViaNimper(
        client,
        req,
        targetUrl,
        cfg,
        keepAlive = req.keepAlive,
        session = session,
        shareHandle = shareHandle
      )
    except CatchableError:
      break

    if not canKeepAlive or not req.keepAlive:
      break

proc enqueueSocket(q: ptr SocketQueue, fd: SocketHandle) =
  acquire(q.lock)
  while q.count >= MaxSocketQueueCapacity:
    wait(q.notFull, q.lock)
  q.buf[q.tail] = fd
  q.tail = (q.tail + 1) mod MaxSocketQueueCapacity
  inc(q.count)
  signal(q.notEmpty)
  release(q.lock)

proc dequeueSocket(q: ptr SocketQueue): SocketHandle =
  acquire(q.lock)
  while q.count == 0:
    wait(q.notEmpty, q.lock)
  result = q.buf[q.head]
  q.head = (q.head + 1) mod MaxSocketQueueCapacity
  dec(q.count)
  signal(q.notFull)
  release(q.lock)

proc workerPoolProc(args: WorkerThreadArgs) {.thread.} =
  {.cast(gcsafe).}:
    let workerSession = newImpersonateSession(
      target = args.cfg.target,
      defaultHeaders = args.cfg.defaultHeaders,
      timeoutMs = args.cfg.timeoutMs,
      connectTimeoutMs = args.cfg.connectTimeoutMs,
      bufferSize = StreamBufferSize,
      followRedirects = args.cfg.followRedirects,
      safeRedirects = args.cfg.safeRedirects,
      maxRedirects = args.cfg.maxRedirects,
      verifySsl = args.cfg.verifySsl,
      proxy = args.cfg.upstreamProxy,
      share = args.shareHandle
    )
    defer:
      workerSession.close()

    while true:
      let fd = dequeueSocket(args.queue)
      if fd == osInvalidSocket:
        break
      let client = newSocket(fd, buffered = true)
      try:
        try:
          client.setSockOpt(OptNoDelay, true)
        except CatchableError:
          discard
        handleClientSocket(client, args.cfg, workerSession, args.shareHandle)
      except CatchableError as e:
        if args.cfg.verbose:
          logError("Worker exception: " & e.msg)
      finally:
        try:
          client.close()
        except CatchableError:
          discard

proc runProxyServer*(cfg: ProxyConfig) =
  ## Initializes `nimper`, the MITM Root CA, a cross-worker `CURLSH*` cache, and a bounded
  ## pre-allocated worker thread pool, then dispatches incoming proxy connections via a queue.
  ensureGlobalInit()
  discard ensureRootCa(cfg.caDir)

  let globalShare = newImpersonateShare(
    shareDns = true,
    shareSslSession = true,
    shareConnect = true,
    shareCookies = false
  )
  defer:
    globalShare.close()

  var queuePtr = cast[ptr SocketQueue](allocShared0(sizeof(SocketQueue)))
  initLock(queuePtr.lock)
  initCond(queuePtr.notEmpty)
  initCond(queuePtr.notFull)

  let numWorkers = max(2, cfg.workerThreads)
  var workers = newSeq[Thread[WorkerThreadArgs]](numWorkers)
  for i in 0 ..< numWorkers:
    createThread(
      workers[i],
      workerPoolProc,
      WorkerThreadArgs(
        workerId: i,
        cfg: cfg,
        queue: queuePtr,
        shareHandle: globalShare.handle
      )
    )

  var server = newSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(cfg.port), cfg.bindAddr)
  server.listen()
  let serverFd = server.getFd()

  logInfo(
    cfg.verbose,
    "Listening on " & cfg.bindAddr & ":" & $cfg.port &
    " with " & $numWorkers & " pooled worker threads"
  )

  while true:
    var clientFd = osInvalidSocket
    try:
      let (fd, _) = nativesockets.accept(serverFd)
      clientFd = fd
    except CatchableError:
      continue

    if clientFd == osInvalidSocket:
      continue

    enqueueSocket(queuePtr, clientFd)
