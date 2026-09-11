# Xitami Web Server

Xitami is iMatix Corporation's free, portable HTTP/FTP server, originally
released in the late 1990s. It uses a single-process, multithreaded design
(built on iMatix's own SMT and SFL libraries) to handle many simultaneous
connections without forking.

Features: virtual hosts, CGI, server-side image maps, standard logging,
password protection, aliases, Perl/Awk/Rexx CGI support, log cycling,
dynamic reconfiguration, user-defined MIME types, and a web-based admin
console.

## Supported platforms

Xitami's source is ANSI C / POSIX and has historically built on:

- Linux
- IBM RS/6000 AIX
- HP-UX
- Digital UNIX (OSF/1)
- SunOS and Solaris
- SCO UNIXWare and OpenServer
- SGI IRIX
- FreeBSD, BSD/OS, NetBSD
- BeOS
- Windows (3.x, 95, NT) and OS/2
- Digital OpenVMS

**Haiku (32/64-bit)** is also supported as of this fork — see
[`HAIKU-PORT.md`](HAIKU-PORT.md) for the porting notes.

## Building from source

Xitami doesn't use autoconf/CMake. A small `c` wrapper script (one copy each
in `src/sfl`, `src/smt`, `src/gsl`) detects your OS via `uname` and picks the
right compiler and flags, and `xibuild` drives the whole build:

```sh
chmod +x xibuild
./xibuild
```

This rebuilds the SFL (Standard Function Library) and GSL (code generator)
packages, then SMT (the server engine) and the `xitami` binary itself, and
finally the test CGI programs, installing everything in the current
directory.

If a build fails on your system, the problem is almost always in
`src/sfl/prelude.h`, which is where nearly all of the platform-specific code
lives — `src/smt` (the server itself), `cgi-src`, and `addons` build
entirely on top of SFL's portability layer.

## Running

```sh
./xitami
```

Then point a browser at `http://localhost/` — you should see the "Welcome
to Xitami" test page. If port 80 is already in use, shift the HTTP/FTP
ports with `-b`:

```sh
./xitami -b 5000     # HTTP on 5080, FTP on 5021
```

Run `./xitami -h` for the full list of command-line options, and see
`xitami.cfg` for the much larger set of runtime configuration options
(virtual hosts, security, logging, CGI, FTP, and so on).

## License

Xitami is copyright (c) 1991-2000 iMatix Corporation and distributed under
the terms in [`license.txt`](license.txt), which (section on modifications)
asks that changes be indicated at the start of each modified source file.
In place of individually annotating every touched file, this notice covers
all of them: this fork modifies the original Xitami source to fix a number
of portability and correctness bugs (see [`HAIKU-PORT.md`](HAIKU-PORT.md))
and to add native HTTPS support via OpenSSL (see
[`HTTPS-PORT.md`](HTTPS-PORT.md)). Git history and the pull requests that
introduced these changes are the authoritative record of exactly what was
modified and why.
