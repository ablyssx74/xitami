# HTTPS support (this fork)

Xitami's original SSL/TLS support was a closed-source "Xitami/Pro" add-on:
the wire protocol between the web server (`smthttp.c`) and its SSL agent
was defined in the open-source tree (`smtsslm.xml`/`.h`/`.c`), and
`smthttp.c` already fully understood that protocol (the `HTTPS` CGI
variable, `SERVER_SECURITY` access logging, the "SSL" checkbox in the web
admin, etc.) - but the SSL agent itself was never shipped as open source.

This fork adds that missing agent (`src/smt/smtssl.c`), implemented with
OpenSSL, so plain HTTPS now works out of the box. It does not change how
`smthttp.c` serves requests in any way - HTTPS is just another way for a
browser to reach the same web server, same document root, same CGI
scripts.

## What's implemented

- Native TLS termination inside Xitami itself (no external stunnel/nginx
  proxy needed) via OpenSSL, minimum protocol version TLS 1.2.
- A second, independent listening port for HTTPS (separate from the plain
  HTTP port), configurable in `xitami.cfg`.
- Full request/response cycle over HTTPS: static pages, CGI (the `HTTPS`
  environment variable is set for CGI scripts), directory browsing,
  password-protected directories - anything that already works over plain
  HTTP.
- Loading either a single certificate file or a full chain file (leaf +
  intermediates), so a Let's Encrypt `fullchain.pem` works directly.

## What's *not* implemented (yet)

- **FTPS** (FTP over TLS) - out of scope for this first pass. Only the
  web server (HTTP) got TLS support; the FTP server (`smtftpc.c`/
  `smtftpd.c`) is unchanged and still plaintext-only.
- **Automatic certificate issuance/renewal.** There is no built-in ACME
  client. You obtain and renew certificates yourself (e.g. with
  `certbot`, see below) and point Xitami at the resulting files; Xitami
  does not talk to Let's Encrypt directly.
- Large file downloads served over HTTPS are read fully into memory for
  the write (unlike the plain-HTTP path, which can stream a file slice
  without loading all of it at once). Fine for ordinary pages; something
  to be aware of if you serve very large files over HTTPS.

## Configuring HTTPS

### Via the web-based admin UI

The Advanced settings page (Configuration → Advanced in the admin UI) has
an "HTTPS port", "SSL certificate (or chain) file", "SSL private key
file" and "SSL chain file (optional)" row, right below the existing
"Enable SSL interface?" checkbox (that checkbox's old "Xitami/Pro only"
note has been updated, since SSL is now genuinely implemented in this
fork). Fill these in the same way as the `xitami.cfg` fields described
below, then Save and Restart as usual.

### Via xitami.cfg directly

Edit the `[Ssl-Http]` section of `xitami.cfg`:

```
[Ssl-Http]
    enabled=1
    port=443
    cert-file=/path/to/fullchain-or-cert.pem
    key-file=/path/to/privkey.pem
    chain-file=
```

- `enabled` - must be `1` to turn HTTPS on. Default is `0` (off), so
  existing installs are unaffected until you opt in.
- `port` - the HTTPS port, shifted by `server:portbase` the same way the
  plain HTTP port is (so `-b 1000` moves HTTPS from 443 to 1443, same as
  it moves HTTP from 80 to 1080).
- `cert-file` / `key-file` - PEM-format certificate and matching private
  key. If your certificate file already contains the full chain (leaf +
  intermediates, e.g. a Let's Encrypt `fullchain.pem`), you can point
  `cert-file` at that directly and leave `chain-file` empty.
- `chain-file` - optional; use this instead of `cert-file` when you keep
  the leaf certificate and the intermediate chain in separate files.

If `enabled=1` but `cert-file`/`key-file` are missing or unreadable, or the
key doesn't match the certificate, Xitami logs an error and the HTTPS
service simply doesn't start - plain HTTP keeps running normally.

Restarting Xitami (or sending it a reload, depending on platform) is
needed to pick up configuration file changes, same as any other setting.

## Getting a certificate with Let's Encrypt / certbot

Xitami does not automate certificate issuance. The straightforward way to
get a real, trusted certificate is `certbot`'s standalone or webroot mode,
run separately (e.g. from cron, or by hand):

```sh
# Webroot mode: works while Xitami is already serving that document root.
# Let's Encrypt's HTTP-01 challenge files get written under
# <document-root>/.well-known/acme-challenge/, and Xitami serves them
# like any other static file - no special configuration needed on the
# Xitami side for this to work.
certbot certonly --webroot -w /path/to/webpages -d example.com

# certbot writes (by default, on Linux):
#   /etc/letsencrypt/live/example.com/fullchain.pem
#   /etc/letsencrypt/live/example.com/privkey.pem
```

Then point `xitami.cfg` at those two files:

```
    cert-file=/etc/letsencrypt/live/example.com/fullchain.pem
    key-file=/etc/letsencrypt/live/example.com/privkey.pem
```

and restart Xitami. Renewal (`certbot renew`, typically via cron/systemd
timer, as certbot itself sets up) still needs Xitami restarted afterwards
to pick up the renewed files - certbot's `--deploy-hook` option is a
convenient way to trigger that automatically.

For local testing (or purely internal use), a self-signed certificate
works fine and needs no external service:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout privkey.pem -out cert.pem -days 365 -subj "/CN=your-hostname"
```

Browsers will show a trust warning for a self-signed certificate; that's
expected and does not affect the TLS connection itself.
