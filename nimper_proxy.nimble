# Package

version       = "0.2.0"
author        = "upi-0"
description   = "HTTP & HTTPS (MITM CONNECT) forward proxy powered by nimper (libcurl-impersonate)"
license       = "MIT"
srcDir        = "src"
bin           = @["nimper_proxy"]

# Dependencies

requires "nim >= 2.0.0"
requires "https://github.com/upi-0/nimper >= 0.2.0"
