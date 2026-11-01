#
#          nimper-proxy — End-to-End Automated Test Suite
#

import std/[unittest, strutils, json, net, nativesockets, os, osproc, tables]
import nimper
import nimper_proxy/[config, certs, server]

type
  UpstreamServerArgs = object
    httpPort: Port
    httpsPort: Port
    caDir: string

  ProxyServerArgs = object
    cfg: ProxyConfig

proc handleUpstreamClient(client: net.Socket, port: Port, isTls: bool) =
  try:
    var reqLine = client.recvLine()
    if reqLine.len == 0:
      return
    let parts = reqLine.strip().splitWhitespace()
    let meth = if parts.len > 0: parts[0] else: "GET"
    let path = if parts.len > 1: parts[1] else: "/"

    var headers = initTable[string, string]()
    var rawHeaders: seq[string] = @[]
    var contentLength = 0
    while true:
      let line = client.recvLine()
      if line == "\r\n" or line == "" or line == "\n":
        break
      let stripped = line.strip()
      rawHeaders.add(stripped)
      let colon = stripped.find(':')
      if colon > 0:
        let k = stripped[0 ..< colon].strip().toLowerAscii()
        let v = stripped[colon + 1 .. ^1].strip()
        headers[k] = v
        if k == "content-length":
          try: contentLength = parseInt(v) except ValueError: contentLength = 0

    var body = ""
    if contentLength > 0:
      body = client.recv(contentLength)

    if path == "/echo":
      let payload = $(%*{
        "scheme": (if isTls: "https" else: "http"),
        "method": meth,
        "path": path,
        "body": body,
        "user_agent": headers.getOrDefault("user-agent", ""),
        "sec_ch_ua": headers.getOrDefault("sec-ch-ua", ""),
        "custom_header": headers.getOrDefault("x-custom-header", ""),
        "impersonate_leaked": headers.getOrDefault("x-impersonate", ""),
        "raw_headers": rawHeaders
      })
      let resp = "HTTP/1.1 200 OK\r\n" &
                 "Content-Type: application/json\r\n" &
                 "X-Upstream-Mode: " & (if isTls: "tls" else: "plain") & "\r\n" &
                 "Content-Length: " & $payload.len & "\r\n" &
                 "Connection: close\r\n\r\n" & payload
      client.send(resp)
    elif path == "/redirect":
      let proto = if isTls: "https" else: "http"
      let loc = proto & "://127.0.0.1:" & $int(port) & "/echo"
      let resp = "HTTP/1.1 302 Found\r\nLocation: " & loc & "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
      client.send(resp)
    else:
      let payload = "not found"
      let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: " & $payload.len & "\r\nConnection: close\r\n\r\n" & payload
      client.send(resp)
  except CatchableError:
    discard
  finally:
    try: client.close() except CatchableError: discard

proc runUpstreamHttpServer(args: UpstreamServerArgs) {.thread.} =
  {.cast(gcsafe).}:
    var srv = newSocket()
    srv.setSockOpt(OptReuseAddr, true)
    srv.bindAddr(args.httpPort, "127.0.0.1")
    srv.listen()
    while true:
      var client: net.Socket
      try:
        srv.accept(client)
        handleUpstreamClient(client, args.httpPort, isTls = false)
      except CatchableError:
        break

proc runUpstreamHttpsServer(args: UpstreamServerArgs) {.thread.} =
  {.cast(gcsafe).}:
    let certPair = getOrCreateHostCert(args.caDir, "127.0.0.1")
    var srv = newSocket()
    srv.setSockOpt(OptReuseAddr, true)
    srv.bindAddr(args.httpsPort, "127.0.0.1")
    srv.listen()
    while true:
      var client: net.Socket
      try:
        srv.accept(client)
        let sslCtx = createServerSslContext(certPair)
        try:
          wrapConnectedSocket(sslCtx, client, handshakeAsServer, "127.0.0.1")
          handleUpstreamClient(client, args.httpsPort, isTls = true)
        finally:
          try: sslCtx.destroyContext() except CatchableError: discard
      except CatchableError:
        break

proc runProxyThread(args: ProxyServerArgs) {.thread.} =
  {.cast(gcsafe).}:
    runProxyServer(args.cfg)

suite "nimper-proxy: Forward Proxy & MITM CONNECT Tests":
  let httpUpstreamPort = Port(19180)
  let httpsUpstreamPort = Port(19443)
  let proxyPort = 19080
  let testCaDir = getTempDir() / "nimper_proxy_test_ca"

  ensureGlobalInit()
  discard ensureRootCa(testCaDir)
  discard getOrCreateHostCert(testCaDir, "127.0.0.1")

  var httpThread: Thread[UpstreamServerArgs]
  var httpsThread: Thread[UpstreamServerArgs]
  var proxyThread: Thread[ProxyServerArgs]

  let upArgs = UpstreamServerArgs(
    httpPort: httpUpstreamPort,
    httpsPort: httpsUpstreamPort,
    caDir: testCaDir
  )
  createThread(httpThread, runUpstreamHttpServer, upArgs)
  createThread(httpsThread, runUpstreamHttpsServer, upArgs)

  var proxyCfg = initDefaultProxyConfig()
  proxyCfg.bindAddr = "127.0.0.1"
  proxyCfg.port = proxyPort
  proxyCfg.defaultHeaders = true
  proxyCfg.followRedirects = false
  proxyCfg.verifySsl = false # Upstream test server uses self-signed test CA
  proxyCfg.caDir = testCaDir

  createThread(proxyThread, runProxyThread, ProxyServerArgs(cfg: proxyCfg))
  sleep(250)

  let proxyUrl = "http://127.0.0.1:" & $proxyPort
  let upstreamHttpBase = "http://127.0.0.1:" & $int(httpUpstreamPort)
  let upstreamHttpsBase = "https://127.0.0.1:" & $int(httpsUpstreamPort)

  test "Plain HTTP forward proxy injects default Firefox 155 fingerprint headers and strips X-Impersonate":
    let cmd = "curl -sS -x " & quoteShell(proxyUrl) &
              " -H 'X-Custom-Header: hello-proxy'" &
              " " & quoteShell(upstreamHttpBase & "/echo")
    let (outp, code) = execCmdEx(cmd)
    check code == 0
    let data = parseJson(outp)
    check data["scheme"].getStr() == "http"
    check data["method"].getStr() == "GET"
    check data["user_agent"].getStr().contains("Firefox/155")
    check data["custom_header"].getStr() == "hello-proxy"
    check data["impersonate_leaked"].getStr() == ""

  test "Per-request X-Impersonate header overrides browser target to Chrome 152":
    let cmd = "curl -sS -x " & quoteShell(proxyUrl) &
              " -H 'X-Impersonate: chrome152'" &
              " " & quoteShell(upstreamHttpBase & "/echo")
    let (outp, code) = execCmdEx(cmd)
    check code == 0
    let data = parseJson(outp)
    check data["user_agent"].getStr().contains("Chrome/152")
    check data["sec_ch_ua"].getStr().contains("152")
    check data["impersonate_leaked"].getStr() == ""

  test "POST request with JSON body via forward proxy":
    let cmd = "curl -sS -X POST -x " & quoteShell(proxyUrl) &
              " -H 'X-Impersonate: safari270'" &
              " -H 'Content-Type: application/json'" &
              " -d '{\"proxy\":\"nimper\"}'" &
              " " & quoteShell(upstreamHttpBase & "/echo")
    let (outp, code) = execCmdEx(cmd)
    check code == 0
    let data = parseJson(outp)
    check data["method"].getStr() == "POST"
    check data["body"].getStr() == """{"proxy":"nimper"}"""
    check data["user_agent"].getStr().contains("Safari")

  test "X-Follow-Redirects per-request override":
    # 1. Default followRedirects=false returns 302
    let cmdNoFollow = "curl -sS -o /dev/null -w '%{http_code}' -x " & quoteShell(proxyUrl) &
                      " " & quoteShell(upstreamHttpBase & "/redirect")
    let (codeStr1, exit1) = execCmdEx(cmdNoFollow)
    check exit1 == 0
    check codeStr1.strip() == "302"

    # 2. X-Follow-Redirects: true follows 302 inside nimper and returns 200 /echo payload
    let cmdFollow = "curl -sS -x " & quoteShell(proxyUrl) &
                    " -H 'X-Follow-Redirects: true'" &
                    " " & quoteShell(upstreamHttpBase & "/redirect")
    let (outp2, exit2) = execCmdEx(cmdFollow)
    check exit2 == 0
    let data2 = parseJson(outp2)
    check data2["path"].getStr() == "/echo"

  test "HTTPS CONNECT MITM termination forwards via nimper with browser impersonation":
    # Test default Firefox 155 and inner -H 'X-Impersonate: chrome152' over HTTPS CONNECT
    let cmdFirefox = "curl -sS -k -x " & quoteShell(proxyUrl) &
                     " -H 'X-Custom-Header: over-mitm-tls'" &
                     " " & quoteShell(upstreamHttpsBase & "/echo")
    let (outFirefox, codeFirefox) = execCmdEx(cmdFirefox)
    check codeFirefox == 0
    let dataFirefox = parseJson(outFirefox)
    check dataFirefox["scheme"].getStr() == "https"
    check dataFirefox["user_agent"].getStr().contains("Firefox/155")
    check dataFirefox["custom_header"].getStr() == "over-mitm-tls"

    let cmdChrome = "curl -sS -k -x " & quoteShell(proxyUrl) &
                    " -H 'X-Impersonate: chrome152'" &
                    " " & quoteShell(upstreamHttpsBase & "/echo")
    let (outChrome, codeChrome) = execCmdEx(cmdChrome)
    check codeChrome == 0
    let dataChrome = parseJson(outChrome)
    check dataChrome["scheme"].getStr() == "https"
    check dataChrome["user_agent"].getStr().contains("Chrome/152")
    check dataChrome["sec_ch_ua"].getStr().contains("152")
