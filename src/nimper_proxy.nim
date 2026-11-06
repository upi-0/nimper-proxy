#
#          nimper-proxy — Main CLI Entry Point
#

import nimper
import nimper_proxy/[config, server]

proc main* {.gcsafe.} =
  let cfg = parseCliConfig()

  if cfg.showHelp:
    echo formatHelpText()
    quit(0)

  if cfg.listTargets:
    echo formatTargetsTable()
    quit(0)

  block:
    ensureGlobalInit()
    runProxyServer(cfg)

when isMainModule:
  main()
