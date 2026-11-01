#
#          nimper-proxy — Main CLI Entry Point
#

import nimper
import nimper_proxy/[config, certs, server]

proc main() =
  let cfg = parseCliConfig()

  if cfg.showHelp:
    echo formatHelpText()
    quit(0)

  if cfg.listTargets:
    echo formatTargetsTable()
    quit(0)

  ensureGlobalInit()
  let caPair = ensureRootCa(cfg.caDir)

  echo "=================================================================="
  echo "  nimper-proxy — HTTP & HTTPS (MITM CONNECT) Browser Proxy"
  echo "=================================================================="
  echo "  Listening on     : http://" & cfg.bindAddr & ":" & $cfg.port
  echo "  Default Target   : " & cfg.target & " (defaultHeaders=" & $cfg.defaultHeaders & ")"
  echo "  Follow Redirects : " & $cfg.followRedirects & " (safeRedirects=" & $cfg.safeRedirects & ")"
  echo "  Verify Upstream  : " & $cfg.verifySsl
  if cfg.upstreamProxy.len > 0:
    echo "  Upstream Proxy   : " & cfg.upstreamProxy
  echo "  libcurl Version  : " & $curl_version()
  echo "  MITM Root CA     : " & caPair.certPath
  echo "------------------------------------------------------------------"
  echo "  Quick Test:"
  echo "    curl -k -x http://" & cfg.bindAddr & ":" & $cfg.port & " https://tls.browserleaks.com/json"
  echo "    curl -k -x http://" & cfg.bindAddr & ":" & $cfg.port & " -H \"X-Impersonate: chrome152\" https://tls.browserleaks.com/json"
  echo "=================================================================="

  runProxyServer(cfg)

when isMainModule:
  main()
