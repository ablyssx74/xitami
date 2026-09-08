# Porting Xitami to Haiku

This is a working log for porting/building the Xitami web server (and its
iMatix SFL/SMT/GSL support libraries) on Haiku's nightly builds.

## Status: confirmed working

- Builds cleanly with `./xibuild` on **Haiku x86_64 (64-bit) nightly** and
  on **Haiku 32-bit nightly**.
- FTP (control + data connections) has been tested and works on the 64-bit
  build.
- The speculative fallback plans below (`__STRICT_ANSI__`, `seteuid`/
  `setegid`, `-lnetwork`) all turned out to be unnecessary — the port as
  written just worked on both real Haiku targets. Left the section in place
  as a record of the reasoning, in case a future Haiku libc/gcc change ever
  makes one of them relevant again.

## Why this was mostly a small, targeted change

Xitami's build has no autoconf/CMake: `xibuild` shells out to per-package
`build` scripts (`src/sfl/build`, `src/gsl/build`, `src/smt/build`), which in
turn call a small `c` wrapper script that autodetects the OS via `uname` and
sets the right compiler/flags. Almost all platform-specific *C* code lives in
`src/sfl` (the Standard Function Library); `src/smt` (the actual server
engine, `xitami.c` and friends), `cgi-src`, and `addons/lrwp` contain no
platform `#ifdef`s at all — they ride entirely on SFL's portability layer.
`src/gsl` (the Otto-style code generator used to produce the `.c` files from
`.l`/`.gsl` templates) is likewise generic.

SFL already had a `__UTYPE_BEOS` port from the BeOS 4.5 days, which was a
useful map of *where* platform code lives, but classic BeOS predates BONE
(Be's networking rewrite): its sockets weren't in the normal file-descriptor
table, `read()`/`write()`/`fcntl(O_NONBLOCK)`/`getsockopt()` didn't work on
them, and `setitimer()`/`seteuid()` didn't exist. Haiku's network stack and
POSIX layer are far more complete than that, so **`__UTYPE_HAIKU` was made a
normal `__UNIX__` variant, not an alias for `__UTYPE_BEOS`** — it falls
through to the same code paths Linux/generic-UNIX use, rather than reusing
those BeOS workarounds.

## Changes made

- **`src/sfl/prelude.h`** (and its generated concatenation, `src/sfl/sfl.h`
  — regenerate with `src/sfl/buildh` after editing any `sfl*.h`, never hand
  edit `sfl.h` directly):
  - Added `__UTYPE_HAIKU` detection from `__HAIKU__` (predefined by GCC on
    Haiku), defining `__UNIX__` alongside it.
  - **Fixed 64-bit detection.** `__IS_64BIT__` was gated purely on
    `__64BIT__`, a macro no mainstream compiler (gcc/clang on Linux, Haiku,
    *BSD, or macOS) ever defines — so `qbyte` (meant to always be exactly
    32 bits) fell back to `unsigned long`, which is 64 bits on any LP64
    UNIX. That silently breaks the MD5/DES/IDEA code in `sflcryp.c` (which
    unions a `qbyte[2]` with an 8-byte `des_cblock`) and the `sock_t`
    socket-handle type on **every 64-bit UNIX**, not just Haiku. Now also
    checks `__LP64__`/`_LP64`/`__x86_64__`/`__aarch64__` etc.
  - Haiku gets `sys/select.h` included, `DOES_SNPRINTF` (Haiku's libroot has
    `snprintf`/`vsnprintf`), and `TIMEZONE 0` (no global `timezone` variable,
    same treatment as the other BSD-derived targets: FreeBSD/NetBSD/BSD/OS).
- **`src/sfl/sflproc.h`**: `FILEHANDLE_MAX` now uses `sysconf(_SC_OPEN_MAX)`
  on Haiku instead of `getdtablesize()`, which Haiku's libroot doesn't
  provide (same treatment as UnixWare).
- **`src/sfl/sflsock.h`**: `argsize_t` (the size-arg type for
  `getsockopt()`/`accept()`/etc.) now uses Haiku's real `socklen_t` instead
  of falling into the `int` fallback, avoiding incompatible-pointer-type
  warnings against Haiku's socket prototypes.
- **`src/sfl/sflsyst.c`**: added a `"UNIX Type: Haiku"` string for
  `sys_system_info()` (used in the admin UI/version banner) — cosmetic only.
- **`src/sfl/c`, `src/smt/c`, `src/gsl/c`** (identical files, three copies):
  added a `Haiku` branch (parallel to the existing `BeOS`/`Linux` branches)
  that's selected when `uname` reports `Haiku`: `CCNAME=gcc`,
  `STDLIBS="-lnetwork -lm"` (Haiku keeps BSD sockets in `libnetwork.so`
  rather than `libroot.so`), and the same `-O2 -Wall` / `-g -Wall` /
  `-s -O2 -Wall` flags used for Linux.

**Everything else** (smt, cgi-src, addons, gsl's own sources) needed no
changes — they should build as soon as SFL does.

## Bugs found along the way

A full build (`./xibuild` on real Haiku, both 32- and 64-bit) surfaces GCC
13's `-Wall` diagnostics against 1996-2000-era C for the first time. Most of
those are cosmetic (unused variables, ambiguous-`else` style notes), but a
few were real, pre-existing bugs — mostly not Haiku-specific, but worth
knowing about if you're running this fork:

- **`sflcryp.c`**: `crypt_data()`'s `CRYPT_MDC` branch copied an
  uninitialized local into the output instead of the buffer
  `mdc_encrypt()`/`mdc_decrypt()` actually wrote to — MDC encrypt/decrypt
  silently produced garbage. Nothing to do with Haiku; plain logic bug.
- **`xixssi.c`**: the SSI `DOCUMENT_NAME` variable included a leading `/` it
  shouldn't have (`file++` where `file + 1` was intended).
- **`smtftpd.c`**: FTP data-connection child-thread event routing read a
  4-byte wire value into a `long` — harmless on the 32-bit systems this code
  ran on for 25 years, but on any 64-bit UNIX (Haiku included) it left half
  the value uninitialized. This is the one genuinely 64-bit-specific bug in
  the list, and exactly the kind of thing porting to 64-bit is for.
- A cluster of `%ld`-vs-`qbyte` format-string mismatches (FTP `SIZE`/`REST`
  replies, DNS debug dumps, request logging, directory-listing temp
  filenames) that only became *visible* once `qbyte` was correctly fixed to
  32 bits (see above) — before that fix they accidentally lined up because
  `qbyte` was itself wrongly 8 bytes wide on 64-bit builds.
- A few buffer-overflow-class `sprintf` calls (an admin-form-driven one in
  `xiadmin.c`, a pipe-temp-filename counter that overflowed every 10,000
  requests, a couple of `long`-sized values into buffers only sized for
  32-bit `long`) switched to `snprintf`/widened.
- Four `strcpy(dst, dst + n)` self-overlapping calls in `sflstr.c` (technically
  undefined behavior, though harmless with a naive forward-copying `strcpy`)
  switched to `memmove`.

## Things that were speculative before real-hardware testing

I had no Haiku toolchain in the environment where this port was written
(Linux/gcc only), so it started as a careful *static* port based on
documented Haiku/BeOS differences, sanity-checked only by compiling every
`sfl/*.c` file both normally and with `-D__HAIKU__` under Linux's headers
(that only catches typos in the `#ifdef` logic, not missing/different Haiku
symbols). It has since built and run successfully on real Haiku 32-bit and
64-bit nightlies, with FTP confirmed working on 64-bit — none of the
fallbacks below were needed, but they're kept here as a record of the
reasoning and a starting point if a future Haiku release ever changes one of
these:

1. **`__STRICT_ANSI__`**. `prelude.h` defines this for any GCC-based
   `__UNIX__` target (this predates Haiku and already applies to Linux) to
   force strict-C89 declarations from system headers. If Haiku's libroot
   headers hide anything Xitami needs behind `__STRICT_ANSI__` (e.g.
   `strdup`, `fileno`, `popen`), you'll see "implicit declaration" warnings
   or, with a stricter GCC 13, hard errors. Fix by adding a
   `!defined(__UTYPE_HAIKU)` guard around that `#define` in `prelude.h`.
2. **`seteuid`/`setegid`** (`src/sfl/sfluid.c`, `src/sfl/sflprocu.imp`).
   These are used to drop/regain privileges around a fixed real/effective
   uid distinction. I assumed Haiku has real `seteuid()`/`setegid()` (they
   are declared in Haiku's `<unistd.h>`) and left `__UTYPE_HAIKU` off the
   existing `__UTYPE_HPUX || __UTYPE_BEOS` fallback-to-`setuid()` branches
   in both files. If linking fails with undefined references, add
   `|| defined (__UTYPE_HAIKU)` to those six spots in `sfluid.c` plus the
   one in `sflprocu.imp`.
3. **`-lnetwork`**. If the linker says libnetwork isn't found, or if Haiku's
   gcc spec file already links it implicitly and complains about a
   duplicate/unused `-lnetwork`, adjust `STDLIBS` in the three `c` scripts.
4. Anything needing a **regenerated `ggcode.h`** to build `src/smt` fully
   (`smtftpl.c`, `smthttpl.c`, `xixxml.c`, `smtschm.c` all `#include` files
   that `xibuild`'s GSL step generates) — this is pre-existing and unrelated
   to the Haiku port; just make sure `xibuild` runs the GSL step before SMT,
   as it already does.

## Building

From the repo root, same as any other UNIX target:

```sh
./xibuild
```

or manually, package by package (each `build` script assumes it's run from
inside that package's directory and needs `libsfl.a`/`sfl.h`/etc. copied in
first — see `xibuild` for the exact sequence):

```sh
cd src/sfl && ./build
cd ../gsl  && cp ../sfl/libsfl.a ../sfl/sfl.h . && ./build
cd ../smt  && cp ../sfl/libsfl.a ../sfl/sfl.h . && cp ../gsl/libgsl.a ../gsl/ggcode.h . && ./build
```

`uname` on Haiku reports `Haiku`, which is all the `c` script needs to pick
the new branch automatically — no manual `UTYPE=Haiku` override required.
