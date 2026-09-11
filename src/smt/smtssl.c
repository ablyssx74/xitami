/*  ----------------------------------------------------------------<Prolog>-
    Name:       smtssl.c
    Title:      SMT SSL agent - OpenSSL-backed implementation
    Package:    Xitami web server

    Written:    2026          (this fork)

    Synopsis:   Implements the "SMTSSL" agent whose wire protocol was
                defined by iMatix in smtsslm.xml/.h/.c (SSL_OPEN,
                SSL_ACCEPTED, SSL_READ_REQUEST, etc) but never had an
                open-source implementation - the original SSL support was
                a closed-source "Xitami/Pro" add-on (see the "Xitami/Pro
                only" label still in the admin UI next to the SSL
                checkbox). smthttp.c already fully understands this
                protocol (server_secure, sslq, ssl_connection, HTTPS CGI
                variable, SERVER_SECURITY logging, etc) - this file is the
                other half that was missing, using OpenSSL.

                Two roles share this one agent (same dialog table):
                  - The "main" thread (name "main", so smthttp.c's
                    thread_lookup ("SMTSSL", "main") finds it) owns the
                    listening socket and accepts new connections.
                  - Each accepted connection gets its own unnamed thread
                    that owns one SSL object, drives the handshake, and
                    then services SSL_READ_REQUEST/SSL_WRITE_REQUEST/
                    SSL_PUT_SLICE events for that one connection.

                Neither role does its own select()/polling: both
                delegate all "wait until this socket is readable/
                writable" waiting to the existing SMT_SOCKET agent via
                its INPUT/OUTPUT methods (exactly how smthttp.c and
                smtftpd.c already wait on plain sockets), so this code
                never risks starving the rest of the single-threaded
                SMT scheduler the way a private blocking select() loop
                could.

    Copyright:  Copyright (c) 1991-2000 iMatix Corporation for the SMT
                kernel this is built on; this file's SSL agent logic is
                new code for this fork, licensed under the same terms
                (see LICENSE.TXT).
 ------------------------------------------------------------------</Prolog>-*/

#include "smtdefn.h"                    /*  SMT definitions                  */
#include "smtsslm.h"                    /*  SMT SSL message functions        */

/*  sfl.h's "#define local static void" (a shorthand this file never uses)
 *  collides with some OpenSSL builds: <openssl/bio.h>, pulled in by
 *  <openssl/ssl.h> below, declares BIO_ADDR parameters literally named
 *  "local" (e.g. "const BIO_ADDR *local"), which the preprocessor then
 *  mangles into "const BIO_ADDR *static void" - breaking the parse.
 *  Undefine it first; nothing in this file needs it.                      */
#undef  local

#include <openssl/ssl.h>
#include <openssl/err.h>

/*- Definitions -------------------------------------------------------------*/

#undef  AGENT_NAME
#ifndef MODULE
#define MODULE  static void             /*  Libero dialog modules            */
#endif

#define AGENT_NAME      "SMTSSL"        /*  Our public name                  */
#define READ_BUFFER_MAX 65535           /*  Largest single SSL_READ_OK block */
                                         /*  (SSL_READ_OK's size field is a   */
                                         /*  'word', i.e. 16 bits)            */

/*  What a thread is currently waiting on smtsock to tell it about          */
enum {
    OP_NONE = 0,                       /*  Not waiting on anything           */
    OP_ACCEPT,                         /*  Master: waiting to accept()       */
    OP_HANDSHAKE,                      /*  Connection: SSL_accept() pending  */
    OP_READ,                           /*  Connection: SSL_read() pending    */
    OP_WRITE,                          /*  Connection: SSL_write() pending   */
    OP_SHUTDOWN                        /*  Connection: SSL_shutdown() pending*/
};

typedef struct {                       /*  Thread context block             */
    Bool
        is_master;                     /*    TRUE for the "main" thread     */
    sock_t
        handle;                        /*    Listening or client socket     */
    SSL
        *ssl;                          /*    OpenSSL session (NULL: master) */
    QID
        reply_to;                      /*    Who opened us / accepted us    */
    int
        pending_op;                    /*    OP_xxx - what we're waiting on */
    /*  Parameters for the pending read, if pending_op == OP_READ           */
    qbyte
        read_max;                      /*    Max. bytes requested           */
    /*  Parameters for the pending write, if pending_op == OP_WRITE         */
    byte
        *write_data;                   /*    Buffer to write (owned by us)  */
    qbyte
        write_size;                    /*    Exact size to write            */
    Bool
        write_is_slice;                /*    TRUE if this came from PUT_SLICE*/
    /*  Parameters for a GET_SLICE ("receive over TLS into a file") in
     *  progress, if pending_op == OP_READ and read_file != NULL - this is
     *  the FTPS upload counterpart to write_is_slice/PUT_SLICE above.     */
    FILE
        *read_file;                    /*    Destination file, or NULL      */
    qbyte
        read_total;                    /*    Bytes written so far           */
} TCB;

/*- Function prototypes -----------------------------------------------------*/

static void  close_connection    (THREAD *thread, Bool send_error);
static void  wait_for_readable   (THREAD *thread, int op);
static void  wait_for_writable   (THREAD *thread, int op);
static void  try_handshake       (THREAD *thread);
static void  try_read            (THREAD *thread);
static void  try_write           (THREAD *thread);
static void  try_shutdown        (THREAD *thread);
static void  report_ssl_error    (THREAD *thread);
static char *ssl_error_string    (SSL *ssl, int rc);
static Bool  load_ssl_context    (void);

/*- Global variables used in this source file only --------------------------*/

static QID
    operq,                             /*  Operator console event queue     */
    sockq;                             /*  Socket i/o agent event queue     */
static SSL_CTX
    *ssl_ctx = NULL;                   /*  Our OpenSSL server context       */
static dbyte
    ssl_port = 0;                      /*  Port we're listening on          */

/*  Configuration, supplied by our caller at smtssl_init() time - agents in
 *  this codebase get their config via init parameters rather than reaching
 *  into a shared global table (see smtftpc_init(root), smthttp_init
 *  (rootdir, cgidir), etc); xitami.c reads these out of xitami.cfg via its
 *  own CONFIG() before calling us, same as it does for those.             */
static char
    *g_port,                           /*  ssl-http:port                    */
    *g_cert_file,                      /*  ssl-http:cert-file               */
    *g_key_file,                       /*  ssl-http:key-file                */
    *g_chain_file;                     /*  ssl-http:chain-file (optional)   */

/*  Event numbers - hand-assigned; there is no Libero/fxgen tool available
 *  to generate these in this environment, so the dialog table below is
 *  written out by hand.  See the state/event tables further down.         */

/*  These MUST be plain sequential constants, not just distinct-looking
 *  variables: method_declare()'s event_number argument is passed BY
 *  VALUE, and the _nextst/_action tables below are indexed by exactly
 *  these numbers - they are not assigned for us anywhere.                 */
enum {
    ssl_open_event = 0,
    start_event,                        /*  Private: hand off accepted socket*/
    ssl_close_event,
    ssl_restart_event,
    ssl_read_request_event,
    ssl_write_request_event,
    ssl_put_slice_event,
    ssl_get_slice_event,                /*  FTPS upload: receive into a file */
    sock_input_ok_event,
    sock_output_ok_event,
    sock_error_event,
    sock_closed_event,
    shutdown_event,
    error_event,
    exception_event
};

#define MAXEVENT        15
#define MAXSTATE        3
#define STATE_INIT      0
#define STATE_RUNNING   1
#define STATE_DEFAULTS  2

MODULE initialise_the_thread     (THREAD *thread);
MODULE terminate_the_thread      (THREAD *thread);
MODULE open_ssl_listener         (THREAD *thread);
MODULE begin_connection          (THREAD *thread);
MODULE close_ssl_agent           (THREAD *thread);
MODULE restart_ssl_listener      (THREAD *thread);
MODULE accept_new_connection     (THREAD *thread);
MODULE start_read_request        (THREAD *thread);
MODULE start_write_request       (THREAD *thread);
MODULE start_put_slice_request   (THREAD *thread);
MODULE start_get_slice_request   (THREAD *thread);
MODULE resume_pending_input      (THREAD *thread);
MODULE resume_pending_output     (THREAD *thread);
MODULE handle_socket_error       (THREAD *thread);

/*---------------------------------------------------------------------------
 *  Hand-written dialog table.
 *
 *  There is no Libero/fxgen tool in this source tree to generate a .d/.i
 *  pair for a brand-new agent (every other SMT agent's tables were
 *  generated by that proprietary 1998 tool, which isn't included here) -
 *  see smtlib.c's execute_thread()/deliver_event() for how these tables
 *  are actually interpreted; this was written by hand to match that
 *  exactly, then verified by building and running the whole server
 *  locally (see HAIKU-PORT.md / HTTPS-PORT.md).
 *
 *  _nextst[state][event] = next state.  _action[state][event] = index (0
 *  = "not handled here, fall through to STATE_DEFAULTS") into _offset[]/
 *  _vector[], the flat list of MODULE indexes (terminated by _STOP) to
 *  run for that transition.
 *---------------------------------------------------------------------------*/

#define _STOP   0xFFFFL

/*  Row order matches the event constants assigned in smtssl_init():
 *  0 open, 1 start, 2 close, 3 restart, 4 read_req, 5 write_req,
 *  6 put_slice, 7 get_slice, 8 input_ok, 9 output_ok, 10 sock_error,
 *  11 sock_closed, 12 shutdown, 13 error, 14 exception                    */

static word _nextst [MAXSTATE][MAXEVENT] =
{
 /*              open start close restrt rdreq wrreq slice gslic inok  outok err   clsd  shut  err   exc  */
 /* INIT     */ { 1,   1,   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    2,    2,    2 },
 /* RUNNING  */ { 1,   1,   1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    2,    2,    2 },
 /* DEFAULTS */ { 2,   2,   2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2 }
};

/*  Action indices: 0 is the reserved "not handled here, fall through to
 *  STATE_DEFAULTS" sentinel (see smtlib.c's execute_thread()) - it is
 *  never actually dereferenced as a real transition.  1..12 are real,
 *  and sock_error/sock_closed deliberately share action 10 (both just
 *  mean "something went wrong with this socket"), same as shutdown/
 *  error/exception all sharing action 11 (terminate) in STATE_DEFAULTS.  */

static word _action [MAXSTATE][MAXEVENT] =
{
 /*              open start close restrt rdreq wrreq slice gslic inok outok err  clsd shut err exc */
 /* INIT     */ { 1,   2,   0,    0,    0,    0,    0,    0,    0,   0,    0,   0,   0,   0,  0  },
 /* RUNNING  */ { 0,   0,   3,    4,    5,    6,    7,    12,   8,   9,    10,  10,  0,   0,  0  },
 /* DEFAULTS */ { 11,  11,  11,   11,   11,   11,   11,   11,   11,  11,   11,  11,  11,  11, 11 }
};

static word _offset [] =
{
    0,                                  /*   0: (unused sentinel)            */
    1,                                  /*   1: open_ssl_listener            */
    3,                                  /*   2: begin_connection             */
    5,                                  /*   3: close_ssl_agent              */
    7,                                  /*   4: restart_ssl_listener         */
    9,                                  /*   5: start_read_request           */
    11,                                 /*   6: start_write_request          */
    13,                                 /*   7: start_put_slice_request      */
    15,                                 /*   8: resume_pending_input         */
    17,                                 /*   9: resume_pending_output        */
    19,                                 /*  10: handle_socket_error          */
    21,                                 /*  11: terminate_the_thread         */
    23                                  /*  12: start_get_slice_request      */
};

static word _vector [] =
{
    _STOP,                              /*  0 */
    0, _STOP,                           /*  1: open_ssl_listener             */
    1, _STOP,                           /*  2: begin_connection              */
    2, _STOP,                           /*  3: close_ssl_agent               */
    3, _STOP,                           /*  4: restart_ssl_listener          */
    4, _STOP,                           /*  5: start_read_request            */
    5, _STOP,                           /*  6: start_write_request           */
    6, _STOP,                           /*  7: start_put_slice_request       */
    7, _STOP,                           /*  8: resume_pending_input          */
    8, _STOP,                           /*  9: resume_pending_output         */
    9, _STOP,                           /* 10: handle_socket_error           */
    10, _STOP,                          /* 11: terminate_the_thread          */
    11, _STOP                           /* 12: start_get_slice_request       */
};

static HOOK *_module [] = {
    open_ssl_listener,                  /*  0 */
    begin_connection,                   /*  1 */
    close_ssl_agent,                    /*  2 */
    restart_ssl_listener,               /*  3 */
    start_read_request,                 /*  4 */
    start_write_request,                /*  5 */
    start_put_slice_request,            /*  6 */
    resume_pending_input,               /*  7 */
    resume_pending_output,              /*  8 */
    handle_socket_error,                /*  9 */
    terminate_the_thread,               /* 10 */
    start_get_slice_request             /* 11 */
};

#if (defined (DEBUG))
static char *_mname [] = {
    "Open-Ssl-Listener", "Begin-Connection", "Close-Ssl-Agent",
    "Restart-Ssl-Listener", "Start-Read-Request", "Start-Write-Request",
    "Start-Put-Slice-Request", "Resume-Pending-Input",
    "Resume-Pending-Output", "Handle-Socket-Error", "Terminate-The-Thread",
    "Start-Get-Slice-Request"
};
static char *_sname [] = { "Init", "Running", "Defaults" };
static char *_ename [] = {
    "Ssl-Open", "Start", "Ssl-Close", "Ssl-Restart", "Ssl-Read-Request",
    "Ssl-Write-Request", "Ssl-Put-Slice", "Ssl-Get-Slice", "Sock-Input-Ok",
    "Sock-Output-Ok", "Sock-Error", "Sock-Closed", "Shutdown", "Error",
    "Exception"
};
#else
static char *_mname [] = {
    "0","1","2","3","4","5","6","7","8","9","10","11"
};
static char *_sname [] = { "0", "1", "2" };
static char *_ename [] = {
    "0","1","2","3","4","5","6","7","8","9","10","11","12","13","14"
};
#endif

#define the_next_event          _the_next_event
#define the_exception_event     _the_exception_event


/*  ---------------------------------------------------------------------[<]-
    Function: smtssl_init

    Synopsis: Initialises the SMTSSL agent with the given certificate/key/
    optional-chain files (PEM format), shared by both HTTPS and FTPS.
    'https_enabled' controls whether smthttp_init()'s own thread_lookup
    ("SMTSSL", "main") will find us and open an HTTPS listener on 'port'
    (call this before smthttp_init() if so).  'ftps_enabled' controls
    whether the certificate/key get loaded for smtftpc's AUTH TLS/FTPS
    support even when HTTPS itself is off - call this before
    smtftpc_init() so smtssl_ready()/smtssl_wrap_socket() work in time.
    Does nothing (and returns 0) if both are FALSE, so it is always safe
    to call unconditionally.  Returns 0 if initialised okay (including
    the disabled no-op case), -1 on error.
    ---------------------------------------------------------------------[>]-*/

int
smtssl_init (Bool https_enabled, Bool ftps_enabled, char *port,
             char *cert_file, char *key_file, char *chain_file)
{
    AGENT
        *agent;
    THREAD
        *thread;
    Bool
        first_time;

    if (!https_enabled && !ftps_enabled)
        return (0);                     /*  SSL not wanted - fine, no-op     */

    /*  Free any previous copies before overwriting - smtssl_init() is
     *  meant to be safely re-callable (see the first_time check just
     *  below), e.g. from smthttp.c's live-Restart path when SSL was
     *  just turned on and the agent doesn't exist yet.  Without this,
     *  each re-call after the first would leak the previous g_port/
     *  g_cert_file/g_key_file/g_chain_file.                              */
    mem_strfree (&g_port);
    mem_strfree (&g_cert_file);
    mem_strfree (&g_key_file);
    mem_strfree (&g_chain_file);
    g_port       = mem_strdup (port);
    g_cert_file  = mem_strdup (cert_file);
    g_key_file   = mem_strdup (key_file);
    g_chain_file = mem_strdup (chain_file);

    first_time = (agent_lookup (AGENT_NAME) == NULL);
    if (first_time)
      {
        if ((agent = agent_declare (AGENT_NAME)) == NULL)
            return (-1);

        agent-> tcb_size    = sizeof (TCB);
        agent-> stack_size  = 0;
        agent-> initialise  = initialise_the_thread;
        agent-> priority    = SMT_PRIORITY_NORMAL;
        agent-> maxevent    = MAXEVENT;
        agent-> maxmodule   = tblsize (_module);
        agent-> maxstate    = MAXSTATE;
        agent-> LR_defaults = STATE_DEFAULTS;
        agent-> LR_nextst   = &_nextst [0][0];
        agent-> LR_action   = &_action [0][0];
        agent-> LR_offset   = _offset;
        agent-> LR_vector   = _vector;
        agent-> LR_module   = _module;
        agent-> LR_mname    = _mname;
        agent-> LR_sname    = _sname;
        agent-> LR_ename    = _ename;

        /*                    Method name        Event value       Priority */
        method_declare (agent, "SHUTDOWN",       shutdown_event,        SMT_PRIORITY_MAX);
        declare_ssl_open        (ssl_open_event,        0);
        method_declare (agent, "_START",         start_event,           0);
        declare_ssl_close       (ssl_close_event,       0);
        declare_ssl_restart     (ssl_restart_event,     0);
        declare_ssl_read_request  (ssl_read_request_event,  0);
        declare_ssl_write_request (ssl_write_request_event, 0);
        declare_ssl_put_slice    (ssl_put_slice_event,   0);
        declare_ssl_get_slice    (ssl_get_slice_event,   0);
        declare_sock_input_ok    (sock_input_ok_event,   0);
        declare_sock_output_ok   (sock_output_ok_event,  0);
        method_declare (agent, "SOCK_ERROR",     sock_error_event,      0);
        method_declare (agent, "SOCK_CLOSED",    sock_closed_event,     0);
        method_declare (agent, "ERROR",          error_event,           0);
        method_declare (agent, "EXCEPTION",      exception_event,       0);

        /*  Ensure that operator console and socket i/o agent are running   */
        if (agent_lookup (SMT_OPERATOR) == NULL)
            smtoper_init ();
        if ((thread = thread_lookup (SMT_OPERATOR, "")) != NULL)
            operq = thread-> queue-> qid;
        else
            return (-1);

        if (agent_lookup (SMT_SOCKET) == NULL)
            smtsock_init ();
        if ((thread = thread_lookup (SMT_SOCKET, "")) != NULL)
            sockq = thread-> queue-> qid;
        else
            return (-1);

        /*  Create the named "main" thread; smthttp_init() looks this up
         *  by name to decide whether HTTPS support is available.  It
         *  stays passive until it gets an SSL_OPEN event from smthttp.   */
        if (thread_create (AGENT_NAME, "main") == NULL)
            return (-1);
      }

    /*  Load the certificate/key now (regardless of whether an HTTPS
     *  listener is wanted) so smtssl_ready()/smtssl_wrap_socket() work
     *  for smtftpc's AUTH TLS support even with HTTPS disabled.  This
     *  is pure local computation (no socket/agent I/O), so unlike
     *  opening the HTTPS listener itself, it doesn't need to go through
     *  the SSL_OPEN event round-trip - do it synchronously right here.  */
    if (!ssl_ctx && !load_ssl_context ())
        return (-1);

    if (first_time)
        sendfmt (&operq, "INFO", "smtssl: SSL agent ready (OpenSSL %s)",
                 OPENSSL_VERSION_TEXT);
    return (0);
}


/*  ---------------------------------------------------------------------[<]-
    Function: smtssl_ready

    Synopsis: Returns TRUE if a certificate/key have been loaded and
    smtssl_wrap_socket() is therefore usable (whether or not the HTTPS
    listener itself is running).
    ---------------------------------------------------------------------[>]-*/

Bool
smtssl_ready (void)
{
    return (ssl_ctx != NULL);
}


/*  ---------------------------------------------------------------------[<]-
    Function: smtssl_wrap_socket

    Synopsis: Starts a TLS server handshake on 'handle', an already-
    connected socket owned by the caller (e.g. an FTP control or data
    connection partway through a plaintext session) - as opposed to a
    connection smtssl accepted itself off its own HTTPS listener.  Same
    protocol as a normal accept: on success, sends SSL_ACCEPTED to
    'reply_to' once the handshake completes; on failure, sends
    SSL_ERROR.  Returns 0 if the request was handed off okay, -1 if SSL
    isn't ready (call smtssl_ready() first) or the thread couldn't be
    created - in either case no reply event will follow.
    ---------------------------------------------------------------------[>]-*/

int
smtssl_wrap_socket (sock_t handle, QID *reply_to)
{
    THREAD
        *child;
    byte
        body [32];
    int
        body_size;

    if (!ssl_ctx)
        return (-1);
    if ((child = thread_create (AGENT_NAME, "")) == NULL)
        return (-1);

    body_size = exdr_write (body, "qqq", (qbyte) handle,
                             (qbyte) reply_to-> node,
                             (qbyte) reply_to-> ident);
    event_send (&child-> queue-> qid, NULL, "_START",
                body, body_size, NULL, NULL, NULL, 0);
    return (0);
}


/*  -------------------------------------------------------------------------
 *  load_ssl_context -- internal
 *
 *  Builds ssl_ctx from g_cert_file/g_key_file/g_chain_file.  Returns
 *  TRUE on success, FALSE (having already logged the reason) on error.
 */

static Bool
load_ssl_context (void)
{
    if (strnull (g_cert_file) || strnull (g_key_file))
      {
        sendfmt (&operq, "ERROR",
            "smtssl: ssl-http:cert-file and ssl-http:key-file must both "
            "be set - SSL not started");
        return (FALSE);
      }
    ssl_ctx = SSL_CTX_new (TLS_server_method ());
    if (ssl_ctx == NULL)
      {
        sendfmt (&operq, "ERROR", "smtssl: SSL_CTX_new failed");
        return (FALSE);
      }
    /*  Never fall back to the historically-broken protocol versions        */
    SSL_CTX_set_min_proto_version (ssl_ctx, TLS1_2_VERSION);

    /*  Prefer the chain file (cert + intermediates) if given, else just
     *  the leaf certificate on its own.                                   */
    if (strused (g_chain_file)
    &&  SSL_CTX_use_certificate_chain_file (ssl_ctx, g_chain_file) != 1)
      {
        sendfmt (&operq, "ERROR", "smtssl: cannot load chain file '%s': %s",
                 g_chain_file, ssl_error_string (NULL, 0));
        goto failed;
      }
    else
    if (strnull (g_chain_file)
    &&  SSL_CTX_use_certificate_file (ssl_ctx, g_cert_file, SSL_FILETYPE_PEM) != 1)
      {
        sendfmt (&operq, "ERROR", "smtssl: cannot load cert file '%s': %s",
                 g_cert_file, ssl_error_string (NULL, 0));
        goto failed;
      }
    if (SSL_CTX_use_PrivateKey_file (ssl_ctx, g_key_file, SSL_FILETYPE_PEM) != 1)
      {
        sendfmt (&operq, "ERROR", "smtssl: cannot load key file '%s': %s",
                 g_key_file, ssl_error_string (NULL, 0));
        goto failed;
      }
    if (SSL_CTX_check_private_key (ssl_ctx) != 1)
      {
        sendfmt (&operq, "ERROR",
                 "smtssl: certificate and private key do not match");
        goto failed;
      }
    return (TRUE);

  failed:
    SSL_CTX_free (ssl_ctx);
    ssl_ctx = NULL;
    return (FALSE);
}


/**************************   INITIALISE THE THREAD   ************************/

MODULE initialise_the_thread (THREAD *thread)
{
    TCB *tcb = thread-> tcb;

    memset (tcb, 0, sizeof (TCB));
    tcb-> pending_op = OP_NONE;
}


/***************************   TERMINATE THE THREAD   ************************/

MODULE terminate_the_thread (THREAD *thread)
{
    TCB *tcb = thread-> tcb;

    if (tcb-> ssl)
      {
        /*  try_shutdown() may already have driven a full, graceful
         *  two-way close_notify exchange to completion before calling us
         *  (see its rc >= 1 case) - SSL_get_shutdown() reports both
         *  SSL_SENT_SHUTDOWN and SSL_RECEIVED_SHUTDOWN when that already
         *  happened.  Calling SSL_shutdown() again here in that case
         *  sends a second, spurious close_notify on an already-closed
         *  TLS connection - harmless to us, but it confused real clients
         *  (FileZilla/GnuTLS, Python's ftplib) into reporting exactly the
         *  "improperly terminated"/SHUTDOWN_WHILE_IN_INIT failures the
         *  graceful-shutdown code was added to fix.  Only attempt it here
         *  when it has not already fully completed - every other caller
         *  of terminate_the_thread() (a failed handshake, a read/write
         *  error) never called SSL_shutdown() at all, so a best-effort
         *  attempt there is still worthwhile.                            */
        if ((SSL_get_shutdown (tcb-> ssl)
            & (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN))
            != (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN))
            SSL_shutdown (tcb-> ssl);
        SSL_free (tcb-> ssl);
        tcb-> ssl = NULL;
      }
    if (tcb-> handle)
      {
        close_socket (tcb-> handle);
        tcb-> handle = 0;
      }
    mem_strfree ((char **) &tcb-> write_data);
    if (tcb-> read_file)
      {
        /*  A GET_SLICE (FTPS upload) was still in progress - the
         *  connection is being torn down out from under it (a client
         *  abort, or the control channel forcing an abort mid-transfer).
         *  Close the file so the fd isn't leaked; leave whatever was
         *  written so far in place, same as a plain-FTP aborted upload
         *  would (there's no "undo the partial write" step there either).*/
        fclose (tcb-> read_file);
        tcb-> read_file = NULL;
      }
    if (tcb-> is_master)
      {
        if (ssl_ctx)
          {
            SSL_CTX_free (ssl_ctx);
            ssl_ctx = NULL;
          }
        /*  g_port/g_cert_file/g_key_file/g_chain_file are mem_strdup'd
         *  once in smtssl_init() and live for the process - free them
         *  here (mirroring ssl_ctx above) so a clean shutdown doesn't
         *  trip mem_assert()'s "everything was freed" check.           */
        mem_strfree (&g_port);
        mem_strfree (&g_cert_file);
        mem_strfree (&g_key_file);
        mem_strfree (&g_chain_file);
      }
    the_next_event = SMT_TERM_EVENT;
}


/****************************   OPEN SSL LISTENER   ***************************/
/*  Handles SSL_OPEN, sent to us by smthttp.  We ignore the supplied
 *  "config" filename (there's no separate SSL config-file format in this
 *  implementation - see ssl-http:port/cert-file/key-file/chain-file in
 *  xitami.cfg instead) and load our own settings straight from the main
 *  configuration table, same as every other agent.                       */

MODULE open_ssl_listener (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    struct_ssl_open
        *params;
    char
        *port_str;

    get_ssl_open (thread-> event-> body, &params);
    free_ssl_open (&params);

    tcb-> is_master = TRUE;
    tcb-> reply_to  = thread-> event-> sender;
    port_str        = g_port;

    /*  The certificate/key are already loaded (or failed to load) at
     *  smtssl_init() time, since FTPS may need ssl_ctx ready with no
     *  HTTPS listener involved at all - see load_ssl_context().        */
    if (!ssl_ctx)
      {
        sendfmt (&operq, "ERROR",
            "smtssl: no usable SSL certificate/key - HTTPS not started");
        send_ssl_error (&tcb-> reply_to, 1);
        the_next_event = SMT_NULL_EVENT;
        return;
      }
    ssl_port = (dbyte) (atoi (strused (port_str)? port_str: "443") + ip_portbase);
    tcb-> handle = passive_TCP (port_str, 5);
    if (tcb-> handle == INVALID_SOCKET)
      {
        sendfmt (&operq, "ERROR", "smtssl: could not open SSL port %s: %s",
                 port_str, sockmsg ());
        send_ssl_error (&tcb-> reply_to, 6);
        the_next_event = SMT_NULL_EVENT;
        return;
      }
    sendfmt (&operq, "INFO", "smtssl: HTTPS service listening on port %u", ssl_port);
    send_ssl_open_ok (&tcb-> reply_to, ssl_port);

    tcb-> pending_op = OP_ACCEPT;
    wait_for_readable (thread, OP_ACCEPT);
    the_next_event = SMT_NULL_EVENT;    /*  Go passive until sock_input_ok   */
}


/*****************************   CLOSE SSL AGENT   ****************************/

MODULE close_ssl_agent (THREAD *thread)
{
    TCB *tcb = thread-> tcb;

    if (tcb-> is_master || tcb-> ssl == NULL)
        /*  Closing the master: shut the whole SSL service down.  Route
         *  through terminate_the_thread() rather than setting
         *  SMT_TERM_EVENT directly - thread_destroy() only frees the raw
         *  TCB block, so skipping it would leak the listening socket
         *  (and, for the master, ssl_ctx/g_cert_file etc).               */
        terminate_the_thread (thread);
    else
        close_connection (thread, FALSE);
}


/**************************   RESTART SSL LISTENER   **************************/
/*  Minimal restart: re-read the cert/key files into the existing context.
 *  Active connections are left alone.                                    */

MODULE restart_ssl_listener (THREAD *thread)
{
    char
        *cert_file, *key_file, *chain_file;

    if (!ssl_ctx)
        return;

    cert_file  = g_cert_file;
    key_file   = g_key_file;
    chain_file = g_chain_file;

    if (strused (chain_file))
        SSL_CTX_use_certificate_chain_file (ssl_ctx, chain_file);
    else
        SSL_CTX_use_certificate_file (ssl_ctx, cert_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file (ssl_ctx, key_file, SSL_FILETYPE_PEM);
    if (SSL_CTX_check_private_key (ssl_ctx) != 1)
        sendfmt (&operq, "ERROR",
            "smtssl: restart - certificate and private key do not match");
    else
        sendfmt (&operq, "INFO", "smtssl: certificate reloaded");
}


/****************************   BEGIN CONNECTION   ****************************/
/*  Handles the private "_START" event: the master thread has accepted a
 *  new connection and created us to own it.  Body is a raw exdr "qq":
 *  the client socket handle, then the master's reply_to node/ident
 *  packed as two qbytes (QID has no exdr type of its own).               */

MODULE begin_connection (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    qbyte
        handle, node, ident;

    exdr_read (thread-> event-> body, "qqq", &handle, &node, &ident);
    tcb-> handle          = (sock_t) handle;
    tcb-> reply_to.node   = (long) node;
    tcb-> reply_to.ident  = (long) ident;
    tcb-> ssl = SSL_new (ssl_ctx);
    if (tcb-> ssl == NULL)
      {
        sendfmt (&operq, "ERROR", "smtssl: SSL_new failed for new connection");
        terminate_the_thread (thread);  /*  Closes tcb-> handle for us       */
        return;
      }
    SSL_set_fd (tcb-> ssl, (int) tcb-> handle);
    try_handshake (thread);
}


/***************************   START READ REQUEST   ***************************/

MODULE start_read_request (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    struct_ssl_read_request
        *params;

    /*  Reply to whoever sent this particular request: begin_connection's
     *  reply_to is the master thread (right for SSL_ACCEPTED), but once
     *  smthttp creates its per-connection child thread, that child - not
     *  the master - is the one waiting for our reply.                   */
    tcb-> reply_to = thread-> event-> sender;

    get_ssl_read_request (thread-> event-> body, &params);
    tcb-> read_max = params-> size;
    if (tcb-> read_max > READ_BUFFER_MAX)
        tcb-> read_max = READ_BUFFER_MAX;
    free_ssl_read_request (&params);

    try_read (thread);
}


/***************************   START WRITE REQUEST   **************************/
/*  A write is all-or-nothing from the caller's point of view (matches
 *  SSL_write()'s own default, non-partial-write behaviour): we always
 *  retry with the identical buffer pointer and length until OpenSSL
 *  reports the whole thing sent, per the OpenSSL manual's requirement
 *  for a retried SSL_write() call.                                       */

MODULE start_write_request (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    struct_ssl_write_request
        *params;

    tcb-> reply_to = thread-> event-> sender;

    get_ssl_write_request (thread-> event-> body, &params);
    mem_strfree ((char **) &tcb-> write_data);
    tcb-> write_size     = (qbyte) params-> size;
    tcb-> write_data     = mem_alloc (tcb-> write_size? tcb-> write_size: 1);
    tcb-> write_is_slice = FALSE;
    if (tcb-> write_data && tcb-> write_size)
        memcpy (tcb-> write_data, params-> data, tcb-> write_size);
    free_ssl_write_request (&params);

    try_write (thread);
}


/*************************   START PUT SLICE REQUEST   ************************/
/*  "Write a slice of a file to the SSL socket."  We read the whole slice
 *  into memory and treat it as one write - simpler and safe, though (unlike
 *  the plain-HTTP path via smttran.c) it means the full slice is held in
 *  RAM at once; fine for ordinary pages, worth knowing for very large
 *  downloads served over HTTPS.                                          */

MODULE start_put_slice_request (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    struct_ssl_put_slice
        *params;
    FILE
        *file;
    qbyte
        want;

    tcb-> reply_to = thread-> event-> sender;

    get_ssl_put_slice (thread-> event-> body, &params);
    mem_strfree ((char **) &tcb-> write_data);
    tcb-> write_data     = NULL;
    tcb-> write_size     = 0;
    tcb-> write_is_slice = TRUE;

    file = fopen (params-> filename, "rb");
    if (file)
      {
        want = params-> end > params-> start? params-> end - params-> start: 0;
        if (params-> start)
            fseek (file, (long) params-> start, SEEK_SET);
        if (want == 0)
          {
            fseek (file, 0, SEEK_END);
            want = (qbyte) ftell (file) - params-> start;
            fseek (file, (long) params-> start, SEEK_SET);
          }
        tcb-> write_data = mem_alloc (want? want: 1);
        if (tcb-> write_data)
            tcb-> write_size = (qbyte) fread (tcb-> write_data, 1, want, file);
        fclose (file);
      }
    else
        sendfmt (&operq, "ERROR", "smtssl: cannot open '%s' for PUT_SLICE: %s",
                 params-> filename, strerror (errno));
    free_ssl_put_slice (&params);

    try_write (thread);
}


/*************************   START GET SLICE REQUEST   ************************/
/*  "Receive data from the SSL socket into a file" - the FTPS upload
 *  (STOR/APPE) counterpart to start_put_slice_request() above.  The
 *  actual receive loop lives in try_read_to_file(); this just opens the
 *  destination file and kicks that off.  maxsize=0 in the request means
 *  "no cap" - quota enforcement for encrypted uploads isn't implemented
 *  yet (see FTPS-PORT.md), so this always accepts the whole upload.      */

MODULE start_get_slice_request (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    struct_ssl_get_slice
        *params;

    tcb-> reply_to = thread-> event-> sender;

    get_ssl_get_slice (thread-> event-> body, &params);
    tcb-> read_total = 0;
    tcb-> read_file   = fopen (params-> filename, params-> append? "ab": "wb");
    if (tcb-> read_file == NULL)
      {
        sendfmt (&operq, "ERROR", "smtssl: cannot open '%s' for GET_SLICE: %s",
                 params-> filename, strerror (errno));
        free_ssl_get_slice (&params);
        send_ssl_error (&tcb-> reply_to, 99);
        terminate_the_thread (thread);
        return;
      }
    free_ssl_get_slice (&params);

    try_read (thread);
}


/**************************   RESUME PENDING INPUT   ***************************/
/*  smtsock has told us our socket is now readable - continue whatever
 *  operation was waiting on that (accept, handshake, or read).           */

MODULE resume_pending_input (THREAD *thread)
{
    TCB *tcb = thread-> tcb;

    switch (tcb-> pending_op)
      {
        case OP_ACCEPT:    accept_new_connection (thread);  break;
        case OP_HANDSHAKE: try_handshake (thread);          break;
        case OP_READ:      try_read (thread);               break;
        case OP_WRITE:     try_write (thread);              break;
        case OP_SHUTDOWN:  try_shutdown (thread);           break;
        default:           the_next_event = SMT_NULL_EVENT; break;
      }
}


/**************************   RESUME PENDING OUTPUT   **************************/
/*  Same as above but for "socket is now writable" - OpenSSL can ask for
 *  either direction during a handshake, or (rarely) mid-write.           */

MODULE resume_pending_output (THREAD *thread)
{
    TCB *tcb = thread-> tcb;

    switch (tcb-> pending_op)
      {
        case OP_HANDSHAKE: try_handshake (thread); break;
        case OP_READ:      try_read (thread);      break;
        case OP_WRITE:     try_write (thread);     break;
        case OP_SHUTDOWN:  try_shutdown (thread);  break;
        default:           the_next_event = SMT_NULL_EVENT; break;
      }
}


/***************************   HANDLE SOCKET ERROR   ***************************/
/*  Covers both SOCK_ERROR and SOCK_CLOSED replies from smtsock.          */

MODULE handle_socket_error (THREAD *thread)
{
    TCB *tcb = thread-> tcb;

    if (tcb-> is_master)
      {
        sendfmt (&operq, "ERROR",
            "smtssl: error waiting on the SSL listening socket - "
            "HTTPS service is stopping");
        terminate_the_thread (thread);
    }
    else
    if (tcb-> pending_op == OP_SHUTDOWN)
        /*  Already gracefully closing (our own close_notify went out,
         *  we were waiting on the peer's) - plenty of peers just reset
         *  the connection once they have their data instead of
         *  completing their own half of the close.  That is not a new
         *  error worth reporting: the caller already got whatever
         *  success/failure notice applies to the actual transfer, long
         *  before we started closing.  Still route through
         *  terminate_the_thread() (not a direct SMT_TERM_EVENT) so
         *  tcb-> ssl/handle/write_data actually get cleaned up -
         *  thread_destroy() only frees the bare TCB block.               */
        terminate_the_thread (thread);
    else
        close_connection (thread, TRUE);
}


/*- Internal helpers ---------------------------------------------------------*/

/*  -------------------------------------------------------------------------
 *  accept_new_connection -- internal
 *
 *  Called (via resume_pending_input) when smtsock says our listening
 *  socket has a connection ready.  Accepts exactly one, hands it to a
 *  new child thread, then re-arms the wait for the next one.
 */

static void
accept_new_connection (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    sock_t
        slave;
    THREAD
        *child;
    byte
        body [32];
    int
        body_size;

    slave = accept_socket (tcb-> handle);
    if (slave != INVALID_SOCKET)
      {
        child = thread_create (AGENT_NAME, "");
        if (child)
          {
            body_size = exdr_write (body, "qqq",
                          (qbyte) slave,
                          (qbyte) tcb-> reply_to.node,
                          (qbyte) tcb-> reply_to.ident);
            event_send (&child-> queue-> qid, NULL, "_START",
                        body, body_size, NULL, NULL, NULL, 0);
        }
        else
            close_socket (slave);
    }
    else
    if (sockerrno != EAGAIN && sockerrno != EWOULDBLOCK)
        sendfmt (&operq, "ERROR", "smtssl: accept() failed: %s", sockmsg ());

    wait_for_readable (thread, OP_ACCEPT);
    the_next_event = SMT_NULL_EVENT;
}


/*  -------------------------------------------------------------------------
 *  try_handshake -- internal
 *
 *  Drives SSL_accept() to completion across as many SOCK_INPUT_OK/
 *  SOCK_OUTPUT_OK round-trips as it takes.
 */

static void
try_handshake (THREAD *thread)
{
    TCB *tcb = thread-> tcb;
    int  rc, ssl_err;

    rc = SSL_accept (tcb-> ssl);
    if (rc == 1)
      {
        /*  Handshake complete - tell smthttp it has a new HTTPS client     */
        const char *cipher = SSL_get_cipher_name (tcb-> ssl);
        tcb-> pending_op = OP_NONE;
        send_ssl_accepted (&tcb-> reply_to, (qbyte) tcb-> handle,
                            "", (char *) (cipher? cipher: "-"), 0);
        the_next_event = SMT_NULL_EVENT;   /*  Wait for a read/write request */
        return;
      }
    ssl_err = SSL_get_error (tcb-> ssl, rc);
    if (ssl_err == SSL_ERROR_WANT_READ)
        wait_for_readable (thread, OP_HANDSHAKE);
    else
    if (ssl_err == SSL_ERROR_WANT_WRITE)
        wait_for_writable (thread, OP_HANDSHAKE);
    else
      {
        report_ssl_error (thread);
        /*  Route through terminate_the_thread() rather than a direct
         *  SMT_TERM_EVENT - thread_destroy() only frees the bare TCB
         *  block, so skipping it would leak tcb-> ssl (never SSL_free'd)
         *  and tcb-> handle (never closed) on every failed handshake -
         *  e.g. a client that rejects our certificate.                   */
        terminate_the_thread (thread);
        return;
      }
    the_next_event = SMT_NULL_EVENT;
}


/*  -------------------------------------------------------------------------
 *  try_read_to_file -- internal
 *
 *  GET_SLICE mode (tcb-> read_file != NULL): the FTPS upload counterpart
 *  to try_write()'s PUT_SLICE mode.  Unlike a plain SSL_READ_REQUEST
 *  (one reply per call, whatever ended up available), this drains
 *  everything currently available in a loop - writing each chunk
 *  straight to the destination file - and only reports back to our
 *  caller once the peer closes the connection (upload complete) or an
 *  error occurs; in between, WANT_READ/WANT_WRITE fall back to the
 *  normal wait-for-socket-then-retry mechanism, same as try_read()'s
 *  ordinary mode.  There is no bound on the whole file's size: like
 *  start_put_slice_request()'s existing download path, only bytes are
 *  addressed here, not RAM - each chunk read is written out and freed
 *  before the next SSL_read(), rather than accumulating in memory.       */

static void
try_read_to_file (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    byte
        buffer [READ_BUFFER_MAX];
    int
        rc, ssl_err;

    FOREVER
      {
        rc = SSL_read (tcb-> ssl, buffer, sizeof (buffer));
        if (rc <= 0)
            break;
        if (fwrite (buffer, 1, (size_t) rc, tcb-> read_file) != (size_t) rc)
          {
            sendfmt (&operq, "ERROR",
                     "smtssl: write error saving uploaded file: %s",
                     strerror (errno));
            fclose (tcb-> read_file);
            tcb-> read_file = NULL;
            send_ssl_error (&tcb-> reply_to, 99);
            terminate_the_thread (thread);
            return;
          }
        tcb-> read_total += (qbyte) rc;
      }
    ssl_err = SSL_get_error (tcb-> ssl, rc);
    if (ssl_err == SSL_ERROR_WANT_READ)
        wait_for_readable (thread, OP_READ);
    else
    if (ssl_err == SSL_ERROR_WANT_WRITE)
        wait_for_writable (thread, OP_READ);
    else
    if (ssl_err == SSL_ERROR_ZERO_RETURN)
      {
        /*  Clean TLS-level close: the client is done sending - the whole
         *  point of a data-channel upload is that its end is signalled
         *  by closing the connection, there being no equivalent of
         *  Content-Length agreed up front.                              */
        tcb-> pending_op = OP_NONE;
        fclose (tcb-> read_file);
        tcb-> read_file = NULL;
        send_ssl_get_slice_ok (&tcb-> reply_to, tcb-> read_total);
        the_next_event = SMT_NULL_EVENT;
        return;
      }
    else
      {
        report_ssl_error (thread);
        fclose (tcb-> read_file);
        tcb-> read_file = NULL;
        terminate_the_thread (thread);  /*  Not a direct SMT_TERM_EVENT -
                                          *  see try_handshake() for why.    */
        return;
      }
    the_next_event = SMT_NULL_EVENT;
}


/*  -------------------------------------------------------------------------
 *  try_read -- internal
 */

static void
try_read (THREAD *thread)
{
    TCB
        *tcb = thread-> tcb;
    byte
        *buffer;
    int
        rc, ssl_err;

    if (tcb-> read_file)
      {
        try_read_to_file (thread);
        return;
      }
    buffer = mem_alloc (tcb-> read_max? tcb-> read_max: 1);
    if (buffer == NULL)
      {
        terminate_the_thread (thread);
        return;
      }
    rc = SSL_read (tcb-> ssl, buffer, (int) tcb-> read_max);
    if (rc > 0)
      {
        tcb-> pending_op = OP_NONE;
        send_ssl_read_ok (&tcb-> reply_to, (dbyte) rc, buffer);
        mem_free (buffer);
        the_next_event = SMT_NULL_EVENT;
        return;
      }
    mem_free (buffer);
    ssl_err = SSL_get_error (tcb-> ssl, rc);
    if (ssl_err == SSL_ERROR_WANT_READ)
        wait_for_readable (thread, OP_READ);
    else
    if (ssl_err == SSL_ERROR_WANT_WRITE)
        wait_for_writable (thread, OP_READ);
    else
    if (ssl_err == SSL_ERROR_ZERO_RETURN)
      {
        /*  Clean TLS-level close: tell smthttp "zero bytes", same as a     */
        /*  plain socket reaching EOF                                      */
        tcb-> pending_op = OP_NONE;
        send_ssl_read_ok (&tcb-> reply_to, 0, (byte *) "");
        the_next_event = SMT_NULL_EVENT;
    }
    else
      {
        report_ssl_error (thread);
        terminate_the_thread (thread);  /*  Not a direct SMT_TERM_EVENT -
                                          *  see try_handshake() for why.    */
        return;
      }
    the_next_event = SMT_NULL_EVENT;
}


/*  -------------------------------------------------------------------------
 *  try_write -- internal
 *
 *  Retries always use the SAME (tcb-> write_data, tcb-> write_size) pair,
 *  as OpenSSL requires when SSL_MODE_ENABLE_PARTIAL_WRITE is not set (the
 *  default we rely on) - so we never advance the buffer between retries.
 */

static void
try_write (THREAD *thread)
{
    TCB *tcb = thread-> tcb;
    int  rc, ssl_err;

    rc = SSL_write (tcb-> ssl, tcb-> write_data, (int) tcb-> write_size);
    if (rc > 0 && (qbyte) rc == tcb-> write_size)
      {
        tcb-> pending_op = OP_NONE;
        if (tcb-> write_is_slice)
            send_ssl_put_slice_ok (&tcb-> reply_to, tcb-> write_size);
        else
            send_ssl_write_ok (&tcb-> reply_to, (qbyte) tcb-> handle, 0);
        mem_strfree ((char **) &tcb-> write_data);
        the_next_event = SMT_NULL_EVENT;
        return;
      }
    ssl_err = SSL_get_error (tcb-> ssl, rc);
    if (ssl_err == SSL_ERROR_WANT_READ)
        wait_for_readable (thread, OP_WRITE);
    else
    if (ssl_err == SSL_ERROR_WANT_WRITE)
        wait_for_writable (thread, OP_WRITE);
    else
      {
        report_ssl_error (thread);
        /*  Not a direct SMT_TERM_EVENT - see try_handshake() for why.
         *  This one matters most in practice: tcb-> write_data (an
         *  mem_alloc'd slice buffer, possibly the whole file) is still
         *  allocated here whenever a client aborts an in-progress
         *  download, and thread_destroy() alone would leak it - exactly
         *  the kind of leak mem_assert() catches at shutdown.            */
        terminate_the_thread (thread);
        return;
      }
    the_next_event = SMT_NULL_EVENT;
}


/*  -------------------------------------------------------------------------
 *  wait_for_readable / wait_for_writable -- internal
 *
 *  Ask the existing SMT_SOCKET agent to tell us (via SOCK_INPUT_OK /
 *  SOCK_OUTPUT_OK / SOCK_ERROR / SOCK_CLOSED) when our socket is ready,
 *  and record what we were trying to do so resume_pending_input/output
 *  can carry on.  This is the same INPUT/OUTPUT method smthttp.c and
 *  smtftpd.c already use for plain sockets.
 */

static void
wait_for_readable (THREAD *thread, int op)
{
    TCB *tcb = thread-> tcb;

    tcb-> pending_op = op;
    send_input (&sockq, 0, (qbyte) tcb-> handle, 0);
}

static void
wait_for_writable (THREAD *thread, int op)
{
    TCB *tcb = thread-> tcb;

    tcb-> pending_op = op;
    send_output (&sockq, 0, (qbyte) tcb-> handle, 0);
}


/*  -------------------------------------------------------------------------
 *  close_connection -- internal
 */

static void
close_connection (THREAD *thread, Bool send_error)
{
    TCB *tcb = thread-> tcb;

    if (send_error)
        send_ssl_error (&tcb-> reply_to, 99);
    try_shutdown (thread);              /*  Attempt a graceful two-way close */
}


/*  -------------------------------------------------------------------------
 *  try_shutdown -- internal
 *
 *  Drives SSL_shutdown() to completion, same retry pattern as
 *  try_handshake()/try_read()/try_write().  A plain SSL_free() +
 *  close_socket() (no SSL_shutdown at all, or one call and no more)
 *  only sends our own close_notify and does not wait for the peer's -
 *  some clients (seen with FileZilla/GnuTLS, and Python's ftplib
 *  calling SSLSocket.unwrap()) treat that as an improperly terminated
 *  connection and fail the whole operation, even though all the data
 *  already arrived correctly.  SSL_shutdown() returns 1 once both
 *  sides' close_notify have been exchanged; until then it behaves
 *  exactly like SSL_read()/SSL_write() with respect to WANT_READ/
 *  WANT_WRITE, so the same wait-for-socket-then-retry loop applies.
 *  Any other outcome (peer resets instead of closing gracefully, or
 *  the socket was already broken) just finishes the close - that is
 *  not a new error worth reporting on top of whatever the caller
 *  already knows.                                                       */

static void
try_shutdown (THREAD *thread)
{
    TCB *tcb = thread-> tcb;
    int  rc, ssl_err;

    rc = SSL_shutdown (tcb-> ssl);
    if (rc >= 1)
      {
        /*  Both sides' close_notify exchanged - route through
         *  terminate_the_thread() rather than a direct SMT_TERM_EVENT so
         *  tcb-> ssl actually gets SSL_free'd and tcb-> handle closed;
         *  thread_destroy() alone only frees the bare TCB block.  This is
         *  the completion path for every ordinary HTTPS/FTPS close, so
         *  skipping it here was the most consequential of these gaps.    */
        terminate_the_thread (thread);
        return;
      }
    ssl_err = SSL_get_error (tcb-> ssl, rc);
    if (ssl_err == SSL_ERROR_WANT_READ)
        wait_for_readable (thread, OP_SHUTDOWN);
    else
    if (ssl_err == SSL_ERROR_WANT_WRITE)
        wait_for_writable (thread, OP_SHUTDOWN);
    else
        terminate_the_thread (thread);
}


/*  -------------------------------------------------------------------------
 *  report_ssl_error / ssl_error_string -- internal
 */

static void
report_ssl_error (THREAD *thread)
{
    TCB *tcb = thread-> tcb;

    sendfmt (&operq, "ERROR", "smtssl: %s", ssl_error_string (tcb-> ssl, 0));
    send_ssl_error (&tcb-> reply_to, (qbyte) ERR_get_error ());
}

static char *
ssl_error_string (SSL *ssl, int rc)
{
    static char
        buffer [256];
    unsigned long
        code = ERR_get_error ();

    if (code)
        ERR_error_string_n (code, buffer, sizeof (buffer));
    else
        snprintf (buffer, sizeof (buffer), "SSL error (no further detail)");
    return (buffer);
}
