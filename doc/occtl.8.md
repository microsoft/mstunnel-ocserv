# occtl(8) -- OpenConnect VPN server control tool


## SYNOPSIS

**occtl** \[OPTIONS...\] \[COMMAND\]


## DESCRIPTION

This a control tool that can be used to send commands to ocserv. When
called without any arguments the tool can be used interactively, where
each command is entered on a command prompt; alternatively the tool
can be called with the command specified as parameter. In the latter
case the tool's exit code will reflect the successful execution of
the command.

## OPTIONS

  * **-s, --socket-file**=_FILE_:
    Specify the server's occtl socket file.
    This option is only needed if you have multiple servers.

  * **-j, --json**:
    Output will be JSON formatted. This option can only be used with  non-interactive  output,
    e.g.,  'occtl  --json show users'.

  * **-n, --no-pager**:
    No pager will be used over output data.

  * **--debug**:
    Provide more verbose information in some commands.

  * **-h, --help**:
    Display usage information and exit.

  * **-v, --version**:
    Output version of program and exit.

## COMMANDS

Commands can be passed as arguments on the command line or entered interactively
at the prompt when occtl is run without a command argument.

### Informational commands

  * **show status**:
    Display server-wide statistics: uptime, number of active sessions,
    number of banned IPs, and other aggregate counters.

  * **show users**:
    List all currently connected users together with their session ID,
    assigned VPN IP address, and connection duration.

  * **show user** _NAME_:
    Display detailed information about a specific connected user, including
    their assigned addresses, group, and traffic statistics.

  * **show id** _ID_:
    Display detailed information about the connection identified by its
    numeric session ID.

  * **show iroutes**:
    List the internal routes that connected clients have advertised to the
    server via the **iroute** per-user/group configuration option.  These
    routes are optionally redistributed to other clients when
    **expose-iroutes** is enabled.

  * **show events**:
    Display a live log of connection and disconnection events.

### Session management

  * **disconnect user** _NAME_:
    Terminate the active VPN connection of the named user.  The user's
    session cookie remains valid; the user can reconnect immediately using
    the same cookie (subject to cookie-timeout).

  * **disconnect id** _ID_:
    Terminate the VPN connection identified by its numeric session ID.
    The session ID is shown by **show users** and **show id**.
    The cookie associated with that session remains valid.

  * **terminate user** _NAME_:
    Disconnect the named user and permanently invalidate all of their session
    cookies.  The user must re-authenticate from scratch on the next
    connection attempt.

  * **terminate id** _ID_:
    Disconnect the connection identified by its numeric session ID and
    invalidate the associated cookie.

  * **terminate session** _SID_:
    Invalidate a session by its session ID (SID) without requiring an active
    connection.  Use this to revoke a cookie held by a client that has
    already disconnected but whose session is still listed by
    **show sessions valid**.

  * **show sessions all**:
    List every known session, including sessions that are still in the
    authenticating state or have been disconnected but whose cookie has not
    yet expired.

  * **show sessions valid**:
    List only the sessions whose cookie is still valid for reconnection.
    A session appears here after authentication completes and disappears when
    the cookie expires or is invalidated by a **terminate** command.

  * **show session** _SID_:
    Display detailed information about the session identified by its session
    ID (SID) string, as shown in **show sessions all** or **show sessions valid**.

### IP ban management

  * **unban ip** _IP_:
    Remove the specified IP address from the ban list immediately, regardless
    of the remaining ban-time.  The address's accumulated ban points are also
    cleared.  See the **max-ban-score**, **ban-time**, and **ban-reset-time**
    directives in ocserv.conf(8).

  * **show ip bans**:
    List all IP addresses that are currently banned.  An IP is banned when
    its accumulated score exceeds **max-ban-score** in ocserv.conf(8).

  * **show ip ban points**:
    List all IP addresses that have accumulated ban points, including those
    below the ban threshold.  Useful for monitoring addresses that are
    approaching the ban limit.

### Server control

  * **reload**:
    Signal the server to re-read its configuration file.  Equivalent to
    sending SIGHUP to the main ocserv process.  Options marked as
    non-reloadable in ocserv.conf(8) are not affected.

  * **stop now**:
    Gracefully shut down the server.  Active VPN sessions are terminated
    before the process exits.

## EXIT STATUS

  * **0**:
    Successful program execution.

  * **1**:
    The operation failed or the command syntax was not valid.

## IMPLEMENTATION NOTES
This tool uses unix domain sockets to connect to ocserv.

## EXAMPLES
The tool can be run interactively when run with no arguments. When arguments are given they are
interpreted as commands. For example:

    $ occtl show users

Any command line arguments to be used as options must precede the command (if any), as shown
below.

    $ occtl --json show users

## AUTHORS

Written by Nikos Mavrogiannopoulos. Many people have contributed to it.

## REPORTING BUGS
Issue tracker: https://gitlab.com/openconnect/ocserv/-/issues

## COPYRIGHT
Copyright (C) 2013-2024 Nikos Mavrogiannopoulos and others, all rights reserved.
This program is released under the terms of the GNU General Public License, version 2.

## SEE ALSO

ocserv(8), ocpasswd(8)
