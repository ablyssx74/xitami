# FTPS support (this fork)

This fork adds Explicit FTPS (RFC 4217 - `AUTH TLS`) to the FTP server
(`smtftpc.c`/`smtftpd.c`), reusing the same SSL agent (`smtssl.c`) added
for [HTTPS](HTTPS-PORT.md). Both the control connection (login, commands)
and data connections (`LIST`/`NLST`/`RETR`) can be encrypted - this is
"full" FTPS, not just a control-channel-only implementation.

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
- Passive-mode (`PASV`) data connections are the tested and supported
  path, which is what essentially every modern FTP client uses.

## What's *not* implemented

- **Encrypted uploads.** `STOR`/`STOU`/`APPE` are refused with a clean
  `504 Command not implemented for that parameter` while `PROT P` is
  active, rather than silently uploading the file in the clear. Turn
  `PROT C` back on (plain data channel) to upload; the control channel -
  and your login credentials - stay encrypted throughout either way.
- **Active mode (`PORT`) data connections under TLS** are unverified.
  Passive mode is what real-world FTPS clients use almost universally;
  active-mode FTPS was not part of this pass.
- A repeated `STOR`/`APPE` attempt while `PROT P` is active consumes one
  passive data port per attempt (the listening socket opened for `PASV`
  is not released when the upload is refused) - it is freed once the
  control connection closes. This is an existing limitation shared with
  other rejection paths in `smtftpc.c` (e.g. quota/permission checks),
  not something new to the TLS support; it is only likely to matter if a
  client retries an encrypted `STOR` many times in one session.
- Some FTPS clients (notably Python's `ftplib.FTP_TLS`) call
  `SSLSocket.unwrap()` on the data connection after each transfer to
  perform an orderly two-way TLS shutdown. Xitami's SSL agent currently
  does a one-sided `SSL_shutdown()` followed immediately by closing the
  socket (the same pattern already used for HTTPS), and some OpenSSL
  3.x/Python combinations report this as `SSLError: [SSL:
  SHUTDOWN_WHILE_IN_INIT]` from that `unwrap()` call. The transfer itself
  completes correctly (all data arrives, and the control channel gets a
  clean `226 Closing data connection`) - this only affects a client's own
  post-transfer cleanup call, not the data. It has not caused problems in
  testing against a raw TLS client that skips `unwrap()`.

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
