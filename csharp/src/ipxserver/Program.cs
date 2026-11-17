// ipxserver - standalone dosbox IPX server
//
// C# port of perl/ipxserver.pl (originally found at
// http://stuff.digriz.org.uk/ipxserver).
//
// Copyright (C) 2010 Alexander Clouter <alex@digriz.org.uk>.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// ---------------------------------------------------------------------------
// Overview of the source files:
//
//   Program.cs      Start-up and shutdown sequence, signal handlers (this file)
//   Options.cs      Command line options, exit codes
//   HelpText.cs     Texts for --help and --man
//   Log.cs          Log file and syslog
//   Privileges.cs   Dropping root privileges (Unix)
//   IpxDatagram.cs  IPX constants, packet decoding/encoding, client record
//   Server.cs       Sockets, main loop and all of the actual server logic
// ---------------------------------------------------------------------------

using System.Runtime.InteropServices;

namespace IpxServer;

internal static class Program
{
    /// <summary>
    /// Exit code for errors nobody anticipated (bugs). Not part of the Perl
    /// version, where the interpreter would have died with a message.
    /// </summary>
    private const int UnexpectedErrorExitCode = 99;

    /// <summary>
    /// SIGUSR1 has no name in .NET's PosixSignal enumeration, but the raw
    /// signal number may be used instead. It is 10 on Linux (x86, ARM, RISC-V)
    /// and 30 on macOS and the BSDs.
    /// </summary>
    private static readonly PosixSignal SigUsr1 =
        (PosixSignal)(OperatingSystem.IsLinux() ? 10 : 30);

    /// <summary>Set when Main() has finished its shutdown work (see OnShutdownSignal).</summary>
    private static readonly ManualResetEventSlim s_mainFinished = new(false);

    /// <summary>
    /// Entry point. The sequence of steps is the same as in the main part of
    /// the Perl script.
    /// </summary>
    internal static int Main(string[] args)
    {
        Log? log = null;
        try
        {
            Options opts = Options.Parse(args);

            // The log file is opened first (still as root, if we are started
            // as such), so every problem from here on can be logged.
            log = new Log(opts.LogFile ?? Options.DefaultLogFile, opts.LogFacility,
                          opts.Verbose, opts.Quiet, logToStderr: opts.NoFork);

            // The Perl version turned itself into a background process
            // (daemon) at this point, unless -n was given. A .NET process
            // cannot fork. That job is left to the service manager of the
            // operating system (systemd etc., see README), which is the way
            // services are run nowadays anyway.
            log.Syslog(LogLevel.Notice, "started");
            log.FileLog("##### Started #####");
            log.FileLog($"Version: {Options.Version}");
            log.FileLog($"Clean up interval: {Server.CleanupInterval} s,"
                        + $" max idle duration: {opts.Idle} s");

            using var server = new Server(opts, log);
            server.OpenSockets();
            if (server.BoundPort4 != 0)
            {
                log.Both(LogLevel.Notice, $"Listening on UDP port {server.BoundPort4} (IPv4)");
            }
            if (server.BoundPort6 != 0)
            {
                log.Both(LogLevel.Notice, $"Listening on UDP port {server.BoundPort6} (IPv6)");
            }

            // After creating the sockets and opening the log file,
            // we no longer need to run as root
            DropRootPrivileges(opts, log);

            using var signals = RegisterSignalHandlers(server);

            server.Run();

            log.Syslog(LogLevel.Notice, "exited");
            log.FileLog("##### Exited Regularly #####");
            return (int)ExitCode.AllOk;
        }
        catch (ProperExitException e)
        {
            return ProperExit(log, (int)e.Code, e.ExitMessage);
        }
        catch (Exception e)
        {
            return ProperExit(log, UnexpectedErrorExitCode, $"Unexpected error: {e}");
        }
        finally
        {
            // This also closes a still open log file:
            log?.Dispose();
            s_mainFinished.Set();
        }
    }

    /// <summary>
    /// Equivalent of proper_exit() of the Perl version: reports the reason for
    /// ending the program (if there is one) and determines the exit code.
    /// </summary>
    private static int ProperExit(Log? log, int errorCode, string? message)
    {
        if (message != null)
        {
            if (errorCode != (int)ExitCode.AllOk)
            {
                bool isCliFault = errorCode == (int)ExitCode.CliParameterFault;
                if (errorCode != (int)ExitCode.CannotWriteToLog && !isCliFault)
                {
                    try
                    {
                        log?.FileLog($"##### Premature ending: {message} #####");
                    }
                    catch (ProperExitException)
                    {
                        // The log file is broken, too. STDERR has to do.
                    }
                }
                Console.Error.WriteLine(message);
            }
            else
            {
                Console.Out.WriteLine(message);
            }
        }
        return errorCode;
    }

    /// <summary>
    /// Equivalent of drop_root_privileges() of the Perl version, see
    /// <see cref="Privileges"/> for the details.
    /// </summary>
    private static void DropRootPrivileges(Options opts, Log log)
    {
        if (!Privileges.IsRoot)
        {
            return;
        }
        string? error = Privileges.DropRootPrivileges(opts.User);
        if (error == null)
        {
            log.Both(LogLevel.Notice, $"Dropped root privileges, now running as user '{opts.User}'");
        }
        else
        {
            // Like the Perl version we continue, but this deserves attention.
            log.Both(LogLevel.Warning,
                     $"Unable to drop root privileges ({error}). STILL RUNNING AS ROOT!");
        }
    }

    /// <summary>
    /// Equivalent of register_signal_handlers() of the Perl version.
    ///
    /// .NET calls the handlers on a separate thread. They therefore only tell
    /// the server what is wanted; the work is done by the main loop itself,
    /// which looks for such requests at least once per second.
    ///
    ///   Unix:    SIGINT, SIGTERM  shutdown
    ///            SIGHUP           disconnect all clients
    ///            SIGUSR1          list all clients in the syslog
    ///   Windows: Ctrl+C, closing the console window, logoff, system
    ///            shutdown         shutdown
    ///            Ctrl+Break       list all clients
    /// </summary>
    /// <returns>An object which removes the handlers again when disposed.</returns>
    private static SignalRegistrations RegisterSignalHandlers(Server server)
    {
        var registrations = new SignalRegistrations();

        void OnShutdownSignal(PosixSignalContext context, string name)
        {
            // Keep the runtime from terminating the process on its own...
            context.Cancel = true;
            server.RequestShutdown(name);
            if (OperatingSystem.IsWindows())
            {
                // ...which Windows does nevertheless in some cases (console
                // closed, logoff, shutdown) as soon as this handler returns.
                // So give the main loop the time to finish properly first.
                s_mainFinished.Wait(TimeSpan.FromSeconds(3));
            }
        }

        registrations.Add(PosixSignal.SIGINT, context => OnShutdownSignal(context, "INT"));
        registrations.Add(PosixSignal.SIGTERM, context => OnShutdownSignal(context, "TERM"));

        if (OperatingSystem.IsWindows())
        {
            // On Windows "SIGHUP" means the console window is being closed
            // and "SIGQUIT" is Ctrl+Break.
            registrations.Add(PosixSignal.SIGHUP, context => OnShutdownSignal(context, "HUP"));
            registrations.Add(PosixSignal.SIGQUIT, context =>
            {
                context.Cancel = true;
                server.RequestClientList();
            });
        }
        else
        {
            registrations.Add(PosixSignal.SIGHUP, context =>
            {
                context.Cancel = true;
                server.RequestDisconnectAll();
            });
            registrations.Add(SigUsr1, context =>
            {
                context.Cancel = true;
                server.RequestClientList();
            });
        }
        return registrations;
    }

    /// <summary>
    /// Keeps the signal registrations alive. A handler is only active as long
    /// as its PosixSignalRegistration object exists.
    /// </summary>
    private sealed class SignalRegistrations : IDisposable
    {
        private readonly List<PosixSignalRegistration> _registrations = [];

        public void Add(PosixSignal signal, Action<PosixSignalContext> handler) =>
            _registrations.Add(PosixSignalRegistration.Create(signal, handler));

        public void Dispose()
        {
            foreach (PosixSignalRegistration registration in _registrations)
            {
                registration.Dispose();
            }
        }
    }
}
