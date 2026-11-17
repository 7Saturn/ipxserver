// ipxserver - standalone dosbox IPX server (C# port of perl/ipxserver.pl)
// See the copyright notice in Program.cs.

using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace IpxServer;

/// <summary>
/// The syslog severities, in the order of the <c>@log_levels</c> array of the
/// Perl version. The numeric values are the ones defined by syslog(3).
/// </summary>
internal enum LogLevel
{
    Emerg = 0,   // system is unusable
    Alert = 1,   // action must be taken immediately
    Crit = 2,    // critical conditions
    Err = 3,     // error conditions
    Warning = 4, // warning conditions
    Notice = 5,  // normal, but significant, condition, see BaseVerbosity
    Info = 6,    // informational message
    Debug = 7,   // verbose-level message
}

/// <summary>
/// All logging of the server. Like the Perl version there are two channels:
///
///  * <see cref="FileLog"/>: the log file. Connects, disconnects and important
///    messages are always written there, independent of the verbosity.
///  * <see cref="Syslog"/>: the system log, filtered by the verbosity level
///    (-v / -q).
///
/// Differences to the Perl version, caused by the platform:
///
///  * .NET has no syslog API. On Unix the messages are therefore sent directly
///    to the datagram socket /dev/log, which is where the C function syslog(3)
///    sends them, too. rsyslog, syslog-ng and systemd-journald all listen there.
///  * Where there is no syslog (Windows, minimal containers) the messages go to
///    STDERR instead, so they are never lost. The same happens with -n, which
///    is what the 'perror' flag of openlog() did in the Perl version.
/// </summary>
internal sealed class Log : IDisposable
{
    /// <summary>If nothing else is set, we start out with LOG_NOTICE.</summary>
    private const int BaseVerbosity = (int)LogLevel.Notice;

    /// <summary>Where syslog(3) delivers its messages on Linux and most other Unixes.</summary>
    private const string SyslogSocketPath = "/dev/log";

    /// <summary>The name we use in the syslog ("ident" of openlog()).</summary>
    private const string Ident = "ipxserver";

    private readonly string _logFileName;
    private readonly int _syslogFacility;
    private readonly bool _logToStderr;

    private StreamWriter? _logFileHandle;
    private Socket? _syslogSocket;

    /// <summary>
    /// Messages up to this level are passed on, the rest is dropped. This is
    /// the equivalent of setlogmask(LOG_UPTO(...)).
    /// </summary>
    public LogLevel MaxLevel { get; }

    /// <summary>For tests: called for every message which passes the level filter.</summary>
    internal Action<LogLevel, string>? SyslogObserver { get; set; }

    /// <param name="logFileName">The path of the log file.</param>
    /// <param name="syslogFacility">0..7 for local0..local7.</param>
    /// <param name="verbose">Number of -v given.</param>
    /// <param name="quiet">Number of -q given.</param>
    /// <param name="logToStderr">True to print syslog messages to STDERR as well (-n).</param>
    /// <param name="useSyslog">False to never contact the system's syslog (tests).</param>
    public Log(string logFileName, int syslogFacility, int verbose, int quiet,
               bool logToStderr, bool useSyslog = true)
    {
        _logFileName = logFileName;
        // The facilities local0..local7 have the numbers 16..23. In a syslog
        // message the facility is stored above the three bits of the severity.
        _syslogFacility = (16 + syslogFacility) << 3;
        MaxLevel = GetSyslogVerbosityLevel(verbose, quiet);

        OpenLogFile();
        if (useSyslog)
        {
            OpenSyslog();
        }
        // No syslog available? Then STDERR is the only place left.
        _logToStderr = logToStderr || (useSyslog && _syslogSocket == null);
    }

    /// <summary>
    /// Equivalent of set_syslog_verbosity_level() of the Perl version:
    /// derives the maximum log level from the -v and -q options.
    /// </summary>
    internal static LogLevel GetSyslogVerbosityLevel(int verbose, int quiet)
    {
        // Verbosity and Quiet combined cancel each other out.
        int derivedLogLevel = BaseVerbosity + verbose - quiet;
        // But that can lead to nonsense, so limit it to what exists.
        return (LogLevel)Math.Clamp(derivedLogLevel, (int)LogLevel.Emerg, (int)LogLevel.Debug);
    }

    /// <summary>
    /// Equivalent of open_log_file() of the Perl version. The file is opened
    /// for appending and every line is flushed immediately, as we don't want
    /// to lose a log file line.
    /// </summary>
    private void OpenLogFile()
    {
        try
        {
            string? directory = Path.GetDirectoryName(Path.GetFullPath(_logFileName));
            if (!string.IsNullOrEmpty(directory))
            {
                // Relevant for the Windows default below %ProgramData%. Under
                // Unix /var/log always exists.
                Directory.CreateDirectory(directory);
            }
            var stream = new FileStream(_logFileName, FileMode.Append, FileAccess.Write,
                                        FileShare.ReadWrite | FileShare.Delete);
            _logFileHandle = new StreamWriter(stream, new UTF8Encoding(false))
            {
                AutoFlush = true,
                NewLine = "\n",
            };
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException
                                      or NotSupportedException or ArgumentException)
        {
            throw new ProperExitException(
                ExitCode.CannotOpenLogFile,
                $"Could not open log file {_logFileName}: {e.Message}");
        }
    }

    /// <summary>
    /// Equivalent of openlog(): connects to the syslog daemon. If there is
    /// none, <see cref="_syslogSocket"/> simply stays null.
    /// </summary>
    private void OpenSyslog()
    {
        if (OperatingSystem.IsWindows() || !File.Exists(SyslogSocketPath))
        {
            return;
        }
        try
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
            socket.Connect(new UnixDomainSocketEndPoint(SyslogSocketPath));
            // Logging must never stall the packet forwarding.
            socket.Blocking = false;
            _syslogSocket = socket;
        }
        catch (SocketException)
        {
            // No syslog daemon is listening. We continue with STDERR.
        }
    }

    /// <summary>
    /// Equivalent of the Perl function syslog(): sends a message to the system
    /// log, if its level passes the verbosity filter.
    /// </summary>
    public void Syslog(LogLevel level, string message)
    {
        if (level > MaxLevel)
        {
            return;
        }
        SyslogObserver?.Invoke(level, message);

        string tag = $"{Ident}[{Environment.ProcessId}]";
        if (_syslogSocket != null)
        {
            // Classic BSD syslog format (RFC 3164), the same which the C
            // function syslog(3) produces: "<priority>timestamp tag: message"
            int priority = _syslogFacility | (int)level;
            string timestamp = DateTime.Now.ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
            // RFC 3164 wants the day of month padded with a space, not a zero.
            if (timestamp[4] == '0')
            {
                timestamp = timestamp[..4] + ' ' + timestamp[5..];
            }
            try
            {
                _syslogSocket.Send(Encoding.UTF8.GetBytes($"<{priority}>{timestamp} {tag}: {message}"));
            }
            catch (SocketException)
            {
                // The syslog daemon is restarting or overloaded. Losing a
                // syslog line is preferable to stopping the service.
            }
        }
        if (_logToStderr)
        {
            Console.Error.WriteLine($"{tag}: {message}");
        }
    }

    /// <summary>
    /// Equivalent of filelog() of the Perl version: appends a line to the log
    /// file, prefixed with the current epoch time stamp.
    /// </summary>
    public void FileLog(string message)
    {
        if (_logFileHandle == null)
        {
            return;
        }
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        try
        {
            _logFileHandle.WriteLine($"{timestamp}: {message}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Do not try to write to the broken file again (Dispose would).
            _logFileHandle = null;
            throw new ProperExitException(
                ExitCode.CannotWriteToLog, $"Could not write to log file {_logFileName}.");
        }
    }

    /// <summary>Convenience: the many places which log to syslog and file at once.</summary>
    public void Both(LogLevel level, string message)
    {
        Syslog(level, message);
        FileLog(message);
    }

    /// <summary>Equivalent of close_log_file() of the Perl version (plus closelog()).</summary>
    public void Dispose()
    {
        try
        {
            _logFileHandle?.Dispose();
        }
        catch (IOException)
        {
            // Nothing sensible is left to be done at this point.
        }
        _logFileHandle = null;
        _syslogSocket?.Dispose();
        _syslogSocket = null;
    }
}
