/*  ----------------------------------------------------------------<Prolog>-
    Name:       smtftpd.c
    Title:      SMT FTP data agent
    Package:    Libero SMT 2.x

    Written:    1996/07/22  iMatix SMT kernel team <smt@imatix.com>
    Revised:    1999/06/27

    Copyright:  Copyright (c) 1991-2000 iMatix Corporation
    License:    This is free software; you can redistribute it and/or modify
                it under the terms of the SMT License Agreement as provided
                in the file LICENSE.TXT.  This software is distributed in
                the hope that it will be useful, but without any warranty.
 ------------------------------------------------------------------</Prolog>-*/

#include "smtdefn.h"                    /*  SMT definitions                  */
#include "smtftpl.h"                    /*  SMT FTP  declaration             */
#include "smtsslm.h"                    /*  SMT SSL message functions (FTPS) */


/*- Definitions -------------------------------------------------------------*/

#undef  AGENT_NAME
#define AGENT_NAME     "smtftpd"        /*  Our public name                  */

#define PUT_FILE_MODE     1
#define GET_FILE_MODE     2
#define APPEND_FILE_MODE  3
#define PASSIVE_MODE      4


typedef struct                          /*  Thread context block:            */
{
    sock_t
        handle;                         /*    Handle for i/o                 */
    int
        transfer_type;                  /*    Type of transfer (PUT, GET ... */
    event_t
        thread_type;                    /*    Thread type indicator          */
    QID
        reply_to,                       /*    Message Queue to reply         */
        sslq;                           /*    Our SMTSSL connection thread   */
    char
        *file_name,                     /*  File name                        */
        *parameters,                    /*  Command parameters               */
        *pipe;                          /*  Transfer pipe, if any            */
    dbyte
        command,                        /*  Ftp command                      */
        file_type,                      /*  File type                        */
        timeout,                        /*  Wait input timeout               */
        data_port;                      /*  Port number of data connection   */
    Bool
        passive,                        /*  TRUE if passive connection       */
        protected_,                     /*  TRUE: wrap data conn. in TLS     */
        tls_connection;                 /*  TRUE once TLS handshake is done  */
    qbyte
        id,                             /*  ID of control connection         */
        file_offset,                    /*  File offset for transfers        */
        data_host,                      /*  Host address of data connection  */
        maxsize;                        /*  Max. size of data transfer       */
} TCB;


/*- Function prototypes -----------------------------------------------------*/

local create_child (THREAD *thread, char *event_name, event_t type);


/*- Global variables used in this source file only --------------------------*/

static TCB
    *tcb;                               /*  Address thread contect block     */
static QID
    operq,                              /*  Operator console event queue     */
    sockq,                              /*  Socket agent event queue         */
    timeq,                              /*  Timer agent event queue          */
    tranq;                              /*  Transfer agent event queue       */
static SYMTAB
    *pasv_port;                         /*  Table of passive ports used      */


#include "smtftpd.d"                    /*  Include dialog data              */


/********************   INITIALISE AGENT - ENTRY POINT   *********************/

/*  ---------------------------------------------------------------------[<]-
    Function: smtftpd_init

    Synopsis: Initialises the FTP data agent.  Returns 0 if initialised
    okay, -1 if there was an error.
    ---------------------------------------------------------------------[>]-*/

int smtftpd_init (void)
{
    AGENT
        *agent;                         /*  Handle for our agent             */
    THREAD
        *thread;                        /*  Handle to various threads        */
#   include "smtftpd.i"                 /*  Include dialog interpreter       */

    /*                      Method name      Event value     Priority        */
    /*  Shutdown event comes from Kernel                                     */
    method_declare (agent, "SHUTDOWN", shutdown_event, SMT_PRIORITY_MAX);

    /*  Reply events from socket agent                                       */
    method_declare (agent, "SOCK_INPUT_OK",    ok_event,           0);
    method_declare (agent, "SOCK_OUTPUT_OK",   ok_event,           0);
    method_declare (agent, "SOCK_READ_OK",     ok_event,           0);
    method_declare (agent, "SOCK_WRITE_OK",    ok_event,           0);
    method_declare (agent, "SOCK_CLOSED",      sock_closed_event,  0);
    method_declare (agent, "SOCK_ERROR",       sock_error_event,   0);
    method_declare (agent, "SOCK_TIMEOUT",     sock_timeout_event, 0);

    /*  Reply events from transfer agent                                     */
    method_declare (agent, "TRAN_PUTF_OK",     finished_event,
                                               SMT_PRIORITY_HIGH);
    method_declare (agent, "TRAN_GETF_OK",     finished_event,
                                               SMT_PRIORITY_HIGH);
    method_declare (agent, "TRAN_CLOSED",      sock_closed_event,
                                               SMT_PRIORITY_HIGH);
    method_declare (agent, "TRAN_ERROR",       sock_error_event,
                                               SMT_PRIORITY_HIGH);

    /*  Reply events from smtssl, for FTPS (PROT P) data connections.
     *  signal_connection_to_control() starts the handshake (once the
     *  client has been told "150 Opening...", never before - see there)
     *  then calls event_wait(); since it is never the last module in its
     *  action list, that parks the thread BETWEEN modules rather than
     *  sending it passive, so whichever of these three replies wakes it
     *  next simply resumes that same list at put_file() - the mapping to
     *  an event number below only has to be some value this agent has
     *  declared, it does not drive a dialog transition here.  put_file()
     *  looks at thread-> event-> name to tell a real SSL_ACCEPTED/
     *  SSL_ERROR apart from an ordinary message.  SSL_PUT_SLICE_OK/
     *  SSL_GET_SLICE_OK/SSL_ERROR (for the actual transfer, also handled
     *  in put_file()/get_file()/append_file()) reuse smttran's own
     *  finished/error events so the rest of the dialog table needs no
     *  changes.                                                           */
    declare_ssl_accepted     (put_file_event, 0);
    declare_ssl_put_slice_ok (finished_event, SMT_PRIORITY_HIGH);
    declare_ssl_get_slice_ok (finished_event, SMT_PRIORITY_HIGH);
    declare_ssl_error        (sock_error_event, SMT_PRIORITY_HIGH);

    /*  Public methods supported by this agent                               */
    method_declare (agent, "FTPD_PASSIVE",     passive_event,
                                               SMT_PRIORITY_LOW);
    method_declare (agent, "FTPD_PUT_FILE",    put_file_event,
                                               SMT_PRIORITY_NORMAL);
    method_declare (agent, "FTPD_GET_FILE",    get_file_event,
                                               SMT_PRIORITY_NORMAL);
    method_declare (agent, "FTPD_APPEND_FILE", append_file_event,
                                               SMT_PRIORITY_NORMAL);
    method_declare (agent, "FTPD_ABORT",       abort_event,
                                               SMT_PRIORITY_HIGH);
    method_declare (agent, "FTPD_CLOSECTRL",   close_control_event,
                                               SMT_PRIORITY_HIGH);

    /*  Private method used to pass initial thread events                    */
    method_declare (agent, "_MASTER",          master_event, 0);

    /*  Ensure that operator console is running, else start it up            */
    smtoper_init ();
    if ((thread = thread_lookup (SMT_OPERATOR, "")) != NULL)
        operq = thread-> queue-> qid;
    else
        return (-1);

    /*  Ensure that socket i/o agent is running, else start it up            */
    smtsock_init ();
    if ((thread = thread_lookup (SMT_SOCKET, "")) != NULL)
        sockq = thread-> queue-> qid;
    else
        return (-1);

    /*  Ensure that timer agent is running, else start it up                 */
    smttime_init ();
    if ((thread = thread_lookup (SMT_TIMER, "")) != NULL)
        timeq = thread-> queue-> qid;
    else
        return (-1);

    /*  Ensure that transfer agent is running, else start it up              */
    smttran_init ();
    if ((thread = thread_lookup (SMT_TRANSFER, "")) != NULL)
        tranq = thread-> queue-> qid;
    else
        return (-1);

    /*  Create initial thread to manage master port                          */
    if ((thread = thread_create (AGENT_NAME, "")) != NULL)
      {
        SEND (&thread-> queue-> qid, "_MASTER", "");
        ((TCB *) thread-> tcb)-> thread_type = master_event;
      }
    else
        return (-1);

    pasv_port = sym_create_table ();

    /*  Signal okay to caller that we initialised okay                       */
    return (0);
}


/*************************   INITIALISE THE THREAD   *************************/

MODULE initialise_the_thread (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    if (tcb-> thread_type == master_event)
      {
        tcb-> transfer_type = 0;
        tcb-> file_name     = NULL;
        tcb-> parameters    = NULL;
        tcb-> pipe          = NULL;
        tcb-> command       = 0;
        tcb-> file_type     = 0;
        tcb-> timeout       = 0;
        tcb-> data_port     = 0;
        tcb-> passive       = 0;
        tcb-> id            = 0;
        tcb-> file_offset   = 0;
        tcb-> data_host     = 0;
        tcb-> maxsize       = 0;
      }
    tcb-> handle = 0;

    /*  FTPS: unlike the fields above, these are NOT part of create_child()'s
     *  explicit parent->child copy list nor of the FTPD_PUT_FILE/GET_FILE/
     *  APPEND_FILE wire messages (protected_ is the one exception - it IS
     *  on the wire and gets set again when the child decodes its own copy
     *  of the message), so unlike protected_, tls_connection/sslq would
     *  otherwise be left as uninitialised memory on a freshly allocated
     *  child thread - zero them unconditionally, for every thread type.  */
    tcb-> protected_     = FALSE;
    tcb-> tls_connection = FALSE;
    memset (&tcb-> sslq, 0, sizeof (tcb-> sslq));
}


/**************************   ABORT FILE TRANSFER   **************************/

MODULE abort_file_transfer (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */
}


/************************   ACCEPT CLIENT CONNECTION   ***********************/

MODULE accept_client_connection (THREAD *thread)
{
    sock_t
        slave_socket;                   /*  Connected socket                 */

    tcb = thread-> tcb;                 /*  Point to thread's context        */
    slave_socket = accept_socket (tcb-> handle);
    if (slave_socket != INVALID_SOCKET)
      {
        close_socket (tcb-> handle);
        tcb-> handle = slave_socket;
      }
    else
    if (sockerrno != EAGAIN)
        raise_exception (exception_event);
}


/*************************   CHECK CONNECTION TYPE   *************************/

MODULE check_connection_type (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    the_next_event = (tcb-> passive)? passive_event: active_event;
}


/***************************   CONNECT TO CLIENT   ***************************/

MODULE connect_to_client (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    send_connect (
        &sockq,                         /*  Send to specified queue          */
        0,                              /*  Timeout for connect              */
        "TCP",                          /*  Protocol type                    */
        NULL, NULL,                     /*  Host and service by name         */
        tcb-> data_port,                /*  Port value                       */
        tcb-> data_host,                /*  Host address value               */
        0);                             /*  Connection tag, not used         */
}


/***************************   OPEN LISTEN SOCKET   **************************/

MODULE open_listen_socket (THREAD *thread)
{
    static char
        port [10];
    Bool
        next_port = FALSE;
    int
        index = 0;

    tcb = thread-> tcb;                 /*  Point to thread's context        */

    tcb-> transfer_type = 0;
    if (tcb-> data_port > ip_portbase)
        tcb-> data_port -= ip_portbase;

    sprintf (port, "%d", tcb-> data_port);
    if (sym_lookup_symbol (pasv_port, port) == NULL)
      {
        next_port = FALSE;
        tcb-> handle = passive_TCP (port, 5);
        index++;
      }
    else
        next_port = TRUE;

    while (index < 200
    &&    (next_port == TRUE || connect_error () == IP_BINDERROR))
      {
        tcb-> data_port++;              /*  Port in use - try next one       */
        sprintf (port, "%d", tcb-> data_port);
        if (sym_lookup_symbol (pasv_port, port) == NULL)
          {
            next_port = FALSE;
            tcb-> handle = passive_TCP (port, 5);
            index++;
          }
        else
            next_port = TRUE;
      }

    if (tcb-> handle == INVALID_SOCKET || index >= 200)
        tcb-> handle = 0;               /*  0 means 'not open'               */
    else
      {
        tcb-> data_port += ip_portbase;
        sym_assume_symbol (pasv_port, port, port);
      }
    the_next_event  = tcb-> handle? ok_event: error_event;
}


/***************************   SET TRANSFER MODE   ***************************/

MODULE set_transfer_mode (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    if (tcb-> transfer_type == PUT_FILE_MODE)
        the_next_event = put_file_mode_event;
    else
    if (tcb-> transfer_type == GET_FILE_MODE)
        the_next_event = get_file_mode_event;
    else
    if (tcb-> transfer_type == APPEND_FILE_MODE)
        the_next_event = append_file_mode_event;
}


/**********************   SIGNAL CONNECTION TO CONTROL   *********************/

MODULE signal_connection_to_control (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    /*  Always tell the control channel the data connection is up FIRST -
     *  this is what makes smtftpc reply "150 Opening..." to the client.
     *  For FTPS (PROT P) downloads that reply has to go out before we
     *  attempt the data-channel TLS handshake: the client (per RFC 4217/
     *  ftplib) only starts its side of the handshake once it has seen
     *  "150", so starting ours first and waiting here would deadlock -
     *  each side waiting on the other to go first.  This module is
     *  always immediately followed by put_file()/get_file()/append_file()
     *  in the same action list (never last), so event_wait() correctly
     *  parks the thread here and resumes directly at that next module
     *  once smtssl replies - see put_file()'s handling of the reply.     */
    SEND (&tcb-> reply_to, "FTPD_CONNECTED", "");

    if (tcb-> protected_ && !tcb-> tls_connection)
      {
        if (smtssl_wrap_socket (tcb-> handle, &thread-> queue-> qid) < 0)
            raise_exception (exception_event);
        else
            event_wait ();
      }
}


/************************   SIGNAL END OF TRANSFER   *************************/

MODULE signal_end_of_transfer (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    SEND (&tcb-> reply_to, "FTPD_END", "");
}


/***********************   SIGNAL ERROR IN TRANSFER   ************************/

MODULE signal_error_in_transfer (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    SEND (&tcb-> reply_to, "FTPD_ERROR", "");
}


/************************   SIGNAL CONNECTION FAILED   ***********************/

MODULE signal_connection_failed (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    sendfmt (&operq, "ERROR", "smtftpd: could not connect to %s:%d",
        sock_ntoa (htonl (tcb-> data_host)),
                          tcb-> data_port);

    SEND (&tcb-> reply_to, "FTPD_ERROR", "");
}


/*************************   WAIT FOR SOCKET INPUT   *************************/

MODULE wait_for_socket_input (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    send_input (&sockq, 0, tcb-> handle, 0);
}


/**************************   CREATE CHILD THREAD   **************************/

MODULE create_child_thread (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    if (tcb-> transfer_type == PUT_FILE_MODE)
        create_child (thread, "FTPD_PUT_FILE", put_file_event);
    else
    if (tcb-> transfer_type == PASSIVE_MODE)
        create_child (thread, "FTPD_PASSIVE",  passive_event);
    else
    if (tcb-> transfer_type == GET_FILE_MODE)
        create_child (thread, "FTPD_GET_FILE", get_file_event);
    else
    if (tcb-> transfer_type == APPEND_FILE_MODE)
        create_child (thread, "FTPD_APPEND_FILE", append_file_event);
    else
        SEND (&tcb-> reply_to, "FTPD_ERROR", "");
}


local
create_child (
    THREAD  *thread,
    char    *event_name,
    event_t type)
{
    THREAD
        *child;                         /*  Handle to child thread           */
    TCB
        *child_tcb;
    static char
        child_name [20];

    sprintf (child_name, "%u", tcb-> id);
    if ((child = thread_create (AGENT_NAME, child_name)) != NULL)
      {
        event_send (
            &child-> queue-> qid,       /*  Send to child thread queue       */
            &thread-> event-> sender,   /*  Queue for reply                  */
            event_name,                 /*  Name of event to send            */
            thread-> event-> body,      /*  Event body                       */
            thread-> event-> body_size, /*    and size                       */
            NULL, NULL, NULL,           /*  No response events               */
            0);                         /*  No timeout                       */
        child_tcb = child-> tcb;
        child_tcb-> thread_type = type;
        child_tcb-> reply_to = tcb-> reply_to;

        child_tcb-> file_name   = tcb-> file_name;
        child_tcb-> parameters  = tcb-> parameters;
        child_tcb-> command     = tcb-> command;
        child_tcb-> file_type   = tcb-> file_type;
        child_tcb-> timeout     = tcb-> timeout;
        child_tcb-> data_port   = tcb-> data_port;
        child_tcb-> passive     = tcb-> passive;
        child_tcb-> id          = tcb-> id;          
        child_tcb-> file_offset = tcb-> file_offset;
        child_tcb-> data_host   = tcb-> data_host;
        child_tcb-> maxsize     = tcb-> maxsize;
        child_tcb-> pipe        = tcb-> pipe;
    
        /*  If tcb-> file_name was allocated, now owned by the child         */
        tcb-> file_name = NULL;
        tcb-> pipe      = NULL;
      }
    else
        SEND (&tcb-> reply_to, "FTPD_ERROR", "");
}


/**************************   GET MESSAGE GET FILE   *************************/

MODULE get_message_get_file (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    mem_strfree (&tcb-> file_name);
    mem_strfree (&tcb-> pipe);
    exdr_read (thread-> event-> body, SMT_FTPD_GETF,
               &tcb-> id,
               &tcb-> passive,
               &tcb-> file_type,
               &tcb-> file_name,
               &tcb-> file_offset,
               &tcb-> data_host,
               &tcb-> data_port,
               &tcb-> protected_,
               &tcb-> maxsize,
               &tcb-> pipe);

    tcb-> transfer_type = GET_FILE_MODE;
    if (tcb-> thread_type != passive_event)
        tcb-> reply_to = thread-> event-> sender;
}


/********************************   GET FILE   *******************************/

MODULE get_file (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    /*  FTPS: same event_wait()/resume trick as put_file() - see the
     *  comment there.  get_file() is GET_FILE_MODE, i.e. an upload
     *  (client -> server, STOR): tell a real SSL_ACCEPTED/SSL_ERROR
     *  reply apart from an ordinary first entry by name, same as
     *  put_file() does.                                                  */
    if (thread-> event && thread-> event-> name)
      {
        if (streq (thread-> event-> name, "SSL_ACCEPTED"))
          {
            tcb-> sslq           = thread-> event-> sender;
            tcb-> tls_connection = TRUE;
          }
        else
        if (streq (thread-> event-> name, "SSL_ERROR"))
          {
            raise_exception (exception_event);
            return;
          }
      }

    if (tcb-> tls_connection)
        /*  FTPS: smttran talks to sockq directly and can't go through
         *  smtssl, so bypass it and reuse smtssl's own get-slice handler
         *  (the upload counterpart of the put-slice handler downloads
         *  already use) instead.  This does not support ASCII
         *  translation, resuming a partial upload (file_offset), or
         *  quotas, unlike the plaintext path below - a known limit,
         *  same shape as put_file()'s equivalent for downloads.         */
        send_ssl_get_slice (&tcb-> sslq, tcb-> file_name, FALSE, 0);
    else
        send_get_file (&tranq,
                       tcb-> handle,
                       tcb-> file_name,
                       (dbyte) (tcb-> file_type == FTP_TYPE_ASCII? 1: 0),
                       tcb-> file_offset,
                       0,
                       FALSE,
                       tcb-> maxsize,
                       tcb-> pipe);
}


/************************   GET MESSAGE APPEND FILE   ************************/

MODULE get_message_append_file (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    mem_strfree (&tcb-> file_name);
    mem_strfree (&tcb-> pipe);
    exdr_read (thread-> event-> body, SMT_FTPD_APPEND,
               &tcb-> id,
               &tcb-> passive,
               &tcb-> file_type,
               &tcb-> file_name,
               &tcb-> data_host,
               &tcb-> data_port,
               &tcb-> protected_,
               &tcb-> maxsize,
               &tcb-> pipe);

    tcb-> transfer_type = APPEND_FILE_MODE;
    if (tcb-> thread_type != passive_event)
        tcb-> reply_to = thread-> event-> sender;
}


/******************************   APPEND FILE   ******************************/

MODULE append_file (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    /*  FTPS: see get_file() - identical trick, this is APPEND_FILE_MODE
     *  (APPE) rather than GET_FILE_MODE (STOR).                          */
    if (thread-> event && thread-> event-> name)
      {
        if (streq (thread-> event-> name, "SSL_ACCEPTED"))
          {
            tcb-> sslq           = thread-> event-> sender;
            tcb-> tls_connection = TRUE;
          }
        else
        if (streq (thread-> event-> name, "SSL_ERROR"))
          {
            raise_exception (exception_event);
            return;
          }
      }

    if (tcb-> tls_connection)
        send_ssl_get_slice (&tcb-> sslq, tcb-> file_name, TRUE, 0);
    else
        send_get_file (&tranq,
                       tcb-> handle,
                       tcb-> file_name,
                       (dbyte) (tcb-> file_type == FTP_TYPE_ASCII? 1: 0),
                       tcb-> file_offset,
                       0,
                       TRUE,
                       tcb-> maxsize,
                       tcb-> pipe);
}


/**************************   GET MESSAGE PUT FILE   *************************/

MODULE get_message_put_file (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    mem_strfree (&tcb-> file_name);
    mem_strfree (&tcb-> pipe);
    exdr_read (thread-> event-> body, SMT_FTPD_PUTF,
               &tcb-> id,
               &tcb-> passive,
               &tcb-> file_type,
               &tcb-> file_name,
               &tcb-> file_offset,
               &tcb-> data_host,
               &tcb-> data_port,
               &tcb-> protected_,
               &tcb-> pipe);

    tcb-> transfer_type = PUT_FILE_MODE;
    if (tcb-> thread_type != passive_event)
        tcb-> reply_to = thread-> event-> sender;
}


/********************************   PUT FILE   *******************************/

MODULE put_file (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    /*  FTPS: when signal_connection_to_control() started a TLS handshake
     *  it called event_wait() right after itself - since it is never the
     *  last module in its action list, that parks the thread there and
     *  resumes directly here (not by re-entering the dialog table) once
     *  smtssl replies.  Tell a real reply apart from an ordinary first
     *  entry (thread-> event is still the original FTPD_PUT_FILE message
     *  in that case) by name; on success record the SSL queue so the
     *  send_ssl_put_slice() call below is taken, on failure raise the
     *  same exception a plaintext connect failure would.                 */
    if (thread-> event && thread-> event-> name)
      {
        if (streq (thread-> event-> name, "SSL_ACCEPTED"))
          {
            tcb-> sslq           = thread-> event-> sender;
            tcb-> tls_connection = TRUE;
          }
        else
        if (streq (thread-> event-> name, "SSL_ERROR"))
          {
            raise_exception (exception_event);
            return;
          }
      }

    if (tcb-> tls_connection)
        /*  FTPS: smttran talks to sockq directly and can't go through
         *  smtssl, so bypass it and reuse smtssl's own put-slice
         *  handler (the same one HTTPS downloads use) instead.  This
         *  does not support ASCII translation or transfer pipes, unlike
         *  the plaintext path below - fine for the common case (binary
         *  file/listing downloads), a known limit for the rest.        */
        send_ssl_put_slice (&tcb-> sslq, tcb-> handle, tcb-> file_name,
                             tcb-> file_offset, 0);
    else
        send_put_file (&tranq,
                       tcb-> handle,
                       tcb-> file_name,
                       (dbyte) (tcb-> file_type == FTP_TYPE_ASCII? 1: 0),
                       tcb-> file_offset,
                       0,                   /*  End... 0 = all of file       */
                       tcb-> pipe);
}


/***********************   SEND EVENT TO CHILD THREAD   **********************/

MODULE send_event_to_child_thread (THREAD *thread)
{
    qbyte
        id;
    THREAD
        *child;                         /*  Handle to child thread           */
    static char
        child_name [20];

    tcb = thread-> tcb;                 /*  Point to thread's context        */

    exdr_read (thread-> event-> body, "q", &id);
    sprintf (child_name, "%u", id);
    child = thread_lookup (AGENT_NAME, child_name);
    if (child)
        event_send (
            &child-> queue-> qid,       /*  Send to specified queue          */
            &tcb-> reply_to,            /*  Queue for reply                  */
            thread-> event-> name,      /*  Name of event to send            */
            thread-> event-> body,      /*  Event body and size              */
            thread-> event-> body_size,
            NULL, NULL, NULL,           /*  No response events               */
            0);                         /*  No timeout                       */
}


/***************************   GET MESSAGE ABORT   ***************************/

MODULE get_message_abort (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    exdr_read (thread-> event-> body, SMT_FTPD_ABORT, &tcb-> id);
    tcb-> reply_to = thread-> event-> sender;
}


/**************************   GET MESSAGE PASSIVE   **************************/

MODULE get_message_passive (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    mem_strfree (&tcb-> file_name);
    mem_strfree (&tcb-> pipe);

    exdr_read (thread-> event-> body, SMT_FTPD_PASSIVE, &tcb-> id,
               &tcb-> data_port, &tcb-> data_host);

    tcb-> reply_to      = thread-> event-> sender;
    tcb-> transfer_type = PASSIVE_MODE;
    tcb-> passive       = TRUE;
}


/*************************   GET CONNECTION HANDLE   *************************/

MODULE get_connection_handle (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    exdr_read (thread-> event-> body, SMT_SOCK_OK, &tcb-> handle, NULL);
}


/******************************   SIGNAL ERROR   *****************************/

MODULE signal_error (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    SEND (&tcb-> reply_to, "FTPD_ERROR", "");
}


/**************************   SIGNAL PASSIVE OPEN   **************************/

MODULE signal_passive_open (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    send_ftpd_pass_ok (&tcb-> reply_to, tcb-> data_host, tcb-> data_port);
}


/************************   SIGNAL ABORT TO CONTROL   ************************/

MODULE signal_abort_to_control (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    SEND (&tcb-> reply_to, "FTPD_ABORTED", "");
}


/*************************   CLOSE DATA CONNECTION   *************************/

MODULE close_data_connection (THREAD *thread)
{
    tcb = thread-> tcb;                 /*  Point to thread's context        */

    if (tcb-> tls_connection)
      {
        /*  The smtssl connection thread, not us, owns this fd (it has
         *  the live SSL object wrapping it) - ask IT to close and clean
         *  up, rather than closing the fd out from under it here (which
         *  would race: the fd could be reassigned to an unrelated new
         *  connection before smtssl's own terminate_the_thread runs its
         *  SSL_shutdown/SSL_free/close_socket).  Clear our own copy of
         *  the handle so terminate_the_thread()'s unconditional close,
         *  below, does not also close it a second time out from under
         *  smtssl.                                                      */
        send_ssl_close (&tcb-> sslq);
        tcb-> handle = 0;
      }
    else
    if (tcb-> handle)
      {
        close_socket (tcb-> handle);
        tcb-> handle = 0;
      }
}


/*************************   TERMINATE THE THREAD   **************************/

MODULE terminate_the_thread (THREAD *thread)
{
    SYMBOL
        *symb_port;
    static char
        port_name [10];

    tcb = thread-> tcb;                 /*  Point to thread's context        */

    /*  FTPS: a successful, non-aborted transfer ends up here directly
     *  (close_data_connection() only sits on the abort path) - so this is
     *  actually the common case for a TLS data connection, not just the
     *  exceptional one.  Closing tcb->handle out from under smtssl here,
     *  the same way close_data_connection() already takes care not to,
     *  would skip SSL_shutdown() entirely: the raw fd goes away with no
     *  close_notify ever sent, which is exactly what left FTPS clients
     *  (FileZilla via GnuTLS, Python's ftplib) seeing a truncated/
     *  "improperly terminated" TLS connection right after a perfectly
     *  good transfer.  Hand off to smtssl the same way for a graceful
     *  close instead of closing the fd directly.                         */
    if (tcb-> tls_connection)
      {
        send_ssl_close (&tcb-> sslq);
        tcb-> handle = 0;
      }
    else
    if (tcb-> handle)
      {
        close_socket (tcb-> handle);
        tcb-> handle = 0;
      }
    mem_strfree (&tcb-> file_name);
    mem_strfree (&tcb-> pipe);

    if (tcb-> thread_type == master_event)
        sym_delete_table (pasv_port);
    else
    if (tcb-> passive)
      {
        tcb-> data_port -= ip_portbase;
        sprintf (port_name, "%d", tcb-> data_port);
        symb_port = sym_lookup_symbol (pasv_port, port_name);
        if (symb_port)
            sym_delete_symbol (pasv_port, symb_port);
      }
    the_next_event = terminate_event;
}

