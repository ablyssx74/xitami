# FTPS support (this fork)

This fork adds Explicit FTPS (RFC 4217 - `AUTH TLS`) to the FTP server
(`smtftpc.c`/`smtftpd.c`), reusing the same SSL agent (`smtssl.c`) added
for [HTTPS](HTTPS-PORT.md). Both the control connection (login, commands)
and data connections (downloads and uploads alike) can be encrypted -
this is "full" FTPS, not just a control-channel-only implementation.

## What's implemented

- `AUTH TLS`: upgrades the existing plaintext control connection to TLS
  in place, same as a browser upgrading a connection with `STARTTLS`.
  Login (`USER`/`PASS`) and all subsequent commands then travel encrypted.
- `PBSZ`/`PROT`: the standard negotiation that follows `AUTH TLS`. `PROT P`
  turns on encryption for data connections (downloads); `PROT C` turns it
  back off (plain data, encrypted control only) - a client can switch
  between the two at any point in the session.
- Encrypted downloads: `RETR`, `LIST` and `NLST` all work over an
  encrypted data connection when `PROT P` is active, reusing the same
  OpenSSL-backed slice-send path HTTPS downloads use.
- Encrypted uploads: `STOR` and `APPE` also work over an encrypted data
  connection when `PROT P` is active, using a receive-side counterpart
  of that same slice mechanism (smtssl's `SSL_GET_SLICE`) - the file is
  written to disk as data arrives, with no size limit imposed by
  buffering it all in memory first.
- Passive-mode (`PASV`) data connections are the tested and supported
  path, which is what essentially every modern FTP client uses.

## What's *not* implemented

- **Quotas are not enforced for encrypted uploads.** The plaintext
  upload path (`smttran`) checks the account's disk-usage quota before
  and during a transfer; the encrypted path does not yet carry that
  check through to smtssl's receive loop, so an account under `PROT P`
  can currently upload past its configured quota. Quota checks still
  apply normally to plaintext uploads (`PROT C`, or FTPS with
  encryption limited to the control channel).
- **`STOU`** (store-unique) is not wired up to the encrypted path - only
  `STOR`/`APPE`.  Plaintext `STOU` is unaffected.
- ASCII translation and resuming a partial upload (`REST` before `STOR`)
  are not supported for encrypted uploads - the received bytes are
  written to the file exactly as received, from the start. Both work
  normally for plaintext uploads and for encrypted downloads.
- **Active mode (`PORT`) data connections under TLS** are unverified.
  Passive mode is what real-world FTPS clients use almost universally;
  active-mode FTPS was not part of this pass.
- A repeated `STOR`/`APPE` attempt that gets refused (e.g. by a
  permission check) while `PROT P` is active consumes one passive data
  port per attempt (the listening socket opened for `PASV` is not
  released when the upload is refused) - it is freed once the control
  connection closes. This is an existing limitation shared with other
  rejection paths in `smtftpc.c`, not something new to the TLS support;
  it is only likely to matter if a client retries a refused encrypted
  upload many times in one session.
- Some FTPS clients (notably Python's `ftplib.FTP_TLS`) call
  `SSLSocket.unwrap()` on the data connection after each transfer to
  perform an orderly two-way TLS shutdown, and this can raise
  `SSLError: [SSL: SHUTDOWN_WHILE_IN_INIT]` even though the transfer
  itself completed correctly (all data arrived, and the control channel
  got a clean `226 Closing data connection`). Xitami's SSL agent does
  perform a full, graceful two-way `SSL_shutdown()` on every connection
  close - this was confirmed, by direct experiment, to be independent
  of that: the failure reproduces identically regardless of TLS version
  (1.2 vs 1.3), whether the data connection's TLS session is resumed
  from the control connection or not, and whether the server's shutdown
  is one-sided or fully graceful. It is a client-side-only check (no
  server round-trip is involved in triggering it) and is a known rough
  edge in how CPython's `ssl` module tracks handshake completion for a
  second `SSLSocket` built with `session=` from another one - which is
  exactly what `ftplib.FTP_TLS` does for every data connection, per RFC
  4217's recommendation to reuse the control connection's session. It
  has not been observed with FileZilla in this fork's own testing; if
  you do hit an equivalent GnuTLS-side symptom there, it is this same
  class of issue, and the actual file transfer should still be intact -
  worth confirming with a checksum if in doubt.

## Configuring FTPS

FTPS reuses the certificate/key configured for HTTPS
(`[Ssl-Http] cert-file`/`key-file`/`chain-file` in `xitami.cfg` - see
[HTTPS-PORT.md](HTTPS-PORT.md)) and just needs its own `enabled` flag:

```
[Ssl-Ftp]
    enabled=1
```

- `enabled` - must be `1` to allow `AUTH TLS` on the FTP control
  connection. Default is `0` (off), so existing installs are unaffected
  until you opt in. The plain FTP service keeps running exactly as
  before regardless of this setting - FTPS is an *additional* capability
  on the same port, not a separate listener.
- No separate port, cert or key settings are needed: unlike HTTPS (which
  listens on its own port), FTPS upgrades the *existing* FTP control
  connection in place via `AUTH TLS`, and reuses `[Ssl-Http]`'s
  certificate.
- If `enabled=1` but `[Ssl-Http]`'s certificate/key are missing,
  unreadable, or mismatched (the same certificate is shared by both), a
  client's `AUTH TLS` command gets a `502 Command not implemented`
  response rather than a broken handshake; plain FTP logins keep working
  normally.

Restarting Xitami is needed to pick up configuration file changes, same
as any other setting.

## Testing it

Any FTPS-capable client works (FileZilla, `lftp`, `curl --ftp-ssl`,
Python's `ftplib.FTP_TLS`). A quick example with `curl`:

```sh
curl --ftp-ssl -k -u anonymous:test@example.com \
    ftp://your-host/ --list-only
```

(`-k` skips certificate verification, appropriate for a self-signed
certificate in testing - see [HTTPS-PORT.md](HTTPS-PORT.md) for getting a
real certificate with Let's Encrypt/certbot, which works the same way for
FTPS since it's the same certificate).
