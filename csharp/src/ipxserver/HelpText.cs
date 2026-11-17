// ipxserver - standalone dosbox IPX server (C# port of perl/ipxserver.pl)
// See the copyright notice in Program.cs.

namespace IpxServer;

/// <summary>
/// The texts shown for -h/--help and --man. In the Perl version these were
/// generated from the POD documentation embedded in the script (pod2usage).
/// </summary>
internal static class HelpText
{
    /// <summary>Short help, shown for -h and after a faulty command line.</summary>
    public static string Usage => $"""
        Usage:
            ipxserver [options]

        Options:
            -h, --help
                Print a brief help message and exit.

            --man
                Print the complete manual and exit.

            -V, --version
                Print version number and exit.

            -v  Make more verbose (state multiple '-v's for more verbosity).

            -q  Make more quiet (state multiple '-q's for less verbosity).

            -l num, --log=num
                Set the syslog local facility (default '0'), valid values range
                from 0 to 7 inclusively. Only relevant on systems with syslog.

            -p num, --port=num
                Set the UDP port to listen on for IPv4 (default {Options.DefaultPort}). On Unix,
                values below 1024 require special privileges, see README.

            -P num, --port6=num
                Set the UDP port to listen on for IPv6 (default: same as -p).
                It may differ from the IPv4 port.

            -4, --ipv4-only
                Only listen on IPv4.

            -6, --ipv6-only
                Only listen on IPv6.

            -u user, --user=user
                If running as root then after opening the UDP ports drop
                privileges to this unprivileged user account (default
                'nobody'). Unix only.

            -i secs, --idle=secs
                As there is no concept of disconnecting with IPXNET we have to
                idle out the connections instead. With this you can set the
                timeout value (default 1800).

            -L file, --logfile=file
                The log file for connects, disconnects and important messages
                (default {Options.DefaultLogFile}).

            -n, --no-fork
                Additionally log to STDERR. (This program never forks, the
                name of the option is kept for compatibility.)
        """;

    /// <summary>Complete manual, shown for --man.</summary>
    public static string Manual => $"""
        NAME
            ipxserver - standalone dosbox IPX server

        DESCRIPTION
            ipxserver provides an alternative to the built in dosbox IPXNET
            server that runs standalone on Windows and Linux. It can listen on
            port 213/udp (the IANA assigned port for IPX over IP tunnelling)
            and serves clients via IPv4 and IPv6 at the same time. All clients
            share one IPX network, no matter which IP version they use.

            Connects, disconnects and important messages are always logged to
            the log file. Besides that, syslog (if the system has one) is also
            filled according to the set log level. With -n, and on systems
            without syslog, these messages are printed to STDERR.

        {Usage}

        SIGNALS
            disconnect all clients
                pkill -HUP ipxserver

            show details about connected clients in syslog
                pkill -USR1 ipxserver       (Windows: press Ctrl+Break)

            shutdown
                pkill ipxserver             (Windows: press Ctrl+C)

        ERROR CODES
            0   Everything went fine, normal operations until normal shutdown.

            1   Could not open socket. Usually that means either there is no
                network interface with the IP version active, the UDP port
                meant to be used is already used by another process, or the
                process lacks the permission to use a port below 1024.

            2   Command line parameter faulty. This means, the provided CLI
                parameters are somehow wrong/unusable.

            3   Not used any more (was: fork failure in the Perl version).

            4   The log file could not be opened.

            5   A log file line could not be written.

            99  Unexpected internal error (a bug, please report it).

        SEE ALSO
            It is worth going over to http://www.dosbox.com/wiki/IPX to read up
            about IPX networking with dosbox.

        COPYRIGHT
            ipxserver - standalone dosbox IPX server

            Copyright (C) 2010 Alexander Clouter <alex@digriz.org.uk>.

            This program is free software; you can redistribute it and/or
            modify it under the terms of the GNU General Public License as
            published by the Free Software Foundation; either version 2 of the
            License, or (at your option) any later version.

            This program is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
            General Public License for more details.
        """;
}
