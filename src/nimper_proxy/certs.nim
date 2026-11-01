#
#          nimper-proxy — MITM Certificate Authority & Leaf Certificate Manager
#

import std/[os, osproc, strutils, locks, net]

type
  CertError* = object of CatchableError

  CertPair* = object
    certPath*: string
    keyPath*: string

var certLock: Lock
initLock(certLock)

proc sanitizeHostFilename*(host: string): string =
  ## Converts a hostname or IP into a safe filename stem.
  result = newStringOfCap(host.len)
  for ch in host.toLowerAscii():
    if ch in {'a'..'z', '0'..'9', '.', '-', '_'}:
      result.add(ch)
    else:
      result.add('_')
  if result.len == 0:
    result = "default_host"

proc isIpAddress*(host: string): bool =
  ## Checks whether `host` is an IPv4 or IPv6 literal.
  try:
    discard parseIpAddress(host)
    result = true
  except CatchableError:
    result = false

proc runOpenSsl(args: string) =
  let cmd = "openssl " & args
  let (output, exitCode) = execCmdEx(cmd)
  if exitCode != 0:
    raise newException(CertError, "openssl command failed (" & $exitCode & "): " & cmd & "\n" & output)

proc ensureRootCa*(caDir: string): CertPair =
  ## Ensures a Root CA key (`ca.key`) and self-signed certificate (`ca.crt`) exist in `caDir`.
  acquire(certLock)
  defer: release(certLock)

  createDir(caDir)
  let caKey = caDir / "ca.key"
  let caCert = caDir / "ca.crt"

  if not (fileExists(caKey) and fileExists(caCert)):
    # Generate 2048-bit RSA CA private key and self-signed Root CA cert valid for 10 years
    let cnfPath = caDir / "ca_ext.cnf"
    writeFile(cnfPath, """
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
C = US
O = Nimper Proxy MITM CA
CN = Nimper Proxy Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier = hash
""")
    runOpenSsl(
      "req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 3650 " &
      "-keyout " & quoteShell(caKey) & " " &
      "-out " & quoteShell(caCert) & " " &
      "-config " & quoteShell(cnfPath)
    )

  # Also ensure a shared leaf private key exists so per-domain cert generation is fast
  let leafKey = caDir / "leaf.key"
  if not fileExists(leafKey):
    runOpenSsl("genrsa -out " & quoteShell(leafKey) & " 2048")

  result = CertPair(certPath: caCert, keyPath: caKey)

proc getOrCreateHostCert*(caDir: string, host: string): CertPair =
  ## Returns the path to a signed leaf certificate and key for `host`, generating and
  ## caching it on disk if it does not already exist.
  let cleanHost = host.strip().toLowerAscii()
  let safeName = sanitizeHostFilename(cleanHost)
  let hostsDir = caDir / "hosts"

  acquire(certLock)
  defer: release(certLock)

  createDir(hostsDir)
  let leafKey = caDir / "leaf.key"
  let leafCert = hostsDir / (safeName & ".crt")

  if fileExists(leafCert) and fileExists(leafKey):
    return CertPair(certPath: leafCert, keyPath: leafKey)

  let caKey = caDir / "ca.key"
  let caCert = caDir / "ca.crt"
  let csrPath = hostsDir / (safeName & ".csr")
  let extPath = hostsDir / (safeName & ".ext")

  let sanEntry =
    if isIpAddress(cleanHost):
      "IP:" & cleanHost
    else:
      "DNS:" & cleanHost & ",DNS:*." & cleanHost

  let cnHost = if cleanHost.len <= 64: cleanHost else: "nimper-proxy.local"

  writeFile(extPath, """
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = """ & sanEntry & "\n")

  runOpenSsl(
    "req -new -key " & quoteShell(leafKey) &
    " -subj " & quoteShell("/C=US/O=Nimper Proxy/CN=" & cnHost) &
    " -out " & quoteShell(csrPath)
  )

  runOpenSsl(
    "x509 -req -in " & quoteShell(csrPath) &
    " -CA " & quoteShell(caCert) &
    " -CAkey " & quoteShell(caKey) &
    " -CAcreateserial " &
    " -out " & quoteShell(leafCert) &
    " -days 825 -sha256 " &
    " -extfile " & quoteShell(extPath)
  )

  try:
    removeFile(csrPath)
    removeFile(extPath)
  except CatchableError:
    discard

  result = CertPair(certPath: leafCert, keyPath: leafKey)

proc createServerSslContext*(certPair: CertPair): SslContext =
  ## Creates an OpenSSL server context using the leaf certificate and private key.
  result = newContext(
    protVersion = protSSLv23,
    verifyMode = CVerifyNone,
    certFile = certPair.certPath,
    keyFile = certPair.keyPath
  )
