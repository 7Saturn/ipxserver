// ipxserver - standalone dosbox IPX server (C# port of perl/ipxserver.pl)
// See the copyright notice in Program.cs.

using System.Globalization;
using System.Reflection;

namespace IpxServer;

/// <summary>
/// The exit codes of the process. They are identical to the ones of the Perl
/// version (see "ERROR CODES" in the help text), so wrapper scripts keep
/// working.
/// </summary>
internal enum ExitCode
{
    /// <summary>Everything went fine, normal operations until normal shutdown.</summary>
    AllOk = 0,
    /// <summary>A UDP socket could not be opened (port in use, no permission, ...).</summary>
    SocketFault = 1,
    /// <summary>The command line parameters are wrong/unusable.</summary>
    CliParameterFault = 2,
    /// <summary>Kept for compatibility only. The C# port never forks, see README.</summary>
    ForkFailure = 3,
    /// <summary>The log file could not be opened.</summary>
    CannotOpenLogFile = 4,
    /// <summary>A log file line could not be written.</summary>
    CannotWriteToLog = 5,
}

/// <summary>
/// Thrown wherever the Perl version called <c>proper_exit()</c>. It is caught
/// in exactly one place (<see cref="Program.Main"/>), which prints the message,
/// closes the log file and ends the process with the given exit code. Using an
/// exception instead of <c>Environment.Exit()</c> keeps the code testable.
/// </summary>
internal sealed class ProperExitException(ExitCode code, string? message = null)
    : Exception(message)
{
    public ExitCode Code { get; } = code;

    /// <summary>The message to print, or null if there is nothing to say.</summary>
    public string? ExitMessage { get; } = message;
}

/// <summary>
/// The command line options. This is the equivalent of the <c>%opts</c> hash
/// and the <c>GetOptions()</c> call of the Perl version.
/// </summary>
internal sealed class Options
{
    /// <summary>
    /// The IANA assigned port for IPX over IP tunnelling (RFC 1234). The Perl
    /// version asks getservbyname('ipx', 'udp') first and falls back to 213;
    /// as /etc/services says 213 as well, the constant is used directly.
    /// </summary>
    public const int DefaultPort = 213;

    /// <summary>-v: verbosity level (number of '-v's given).</summary>
    public int Verbose { get; set; }

    /// <summary>-q: quiet level (number of '-q's given).</summary>
    public int Quiet { get; set; }

    /// <summary>-l: syslog local facility (local0 .. local7).</summary>
    public int LogFacility { get; set; }

    /// <summary>-p: UDP port to be used for incoming IPv4 connections.</summary>
    public int Port { get; set; } = DefaultPort;

    /// <summary>
    /// -P: UDP port to be used for incoming IPv6 connections. Null means
    /// "not given", in which case the IPv4 port is used (see <see cref="Port6"/>).
    /// </summary>
    public int? Port6Option { get; set; }

    /// <summary>The effective IPv6 port: -P if given, otherwise the same as -p.</summary>
    public int Port6 => Port6Option ?? Port;

    /// <summary>-4: only open the IPv4 socket.</summary>
    public bool Ipv4Only { get; set; }

    /// <summary>-6: only open the IPv6 socket.</summary>
    public bool Ipv6Only { get; set; }

    /// <summary>-u: user to drop to, once the sockets are created (Unix, root only).</summary>
    public string User { get; set; } = "nobody";

    /// <summary>-i: max duration in seconds after which an idle client is dropped.</summary>
    public long Idle { get; set; } = 1800;

    /// <summary>-n: additionally log to STDERR (the Perl version also did not fork then).</summary>
    public bool NoFork { get; set; }

    /// <summary>-L: path of the log file. Null means the platform default.</summary>
    public string? LogFile { get; set; }

    /// <summary>The version of this program, taken from the assembly (see Directory.Build.props).</summary>
    public static string Version { get; } =
        typeof(Options).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "unknown";

    /// <summary>
    /// The log file used if -L is not given. Unix: the same file as the Perl
    /// version. Windows has no /var/log, there the ProgramData folder is used.
    /// </summary>
    public static string DefaultLogFile =>
        OperatingSystem.IsWindows()
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ipxserver", "ipxserver.log")
            : "/var/log/ipxserver.log";

    /// <summary>
    /// Parses the command line. Equivalent of GetOptions() plus
    /// perform_parameter_sanity_check() of the Perl version.
    ///
    /// Supported notations (like Getopt::Long, options are case sensitive):
    ///   -p 213      --port 213      --port=213      -p213 is NOT supported
    ///   -v -v -v    -vvv (flags without a value may be bundled)
    /// </summary>
    /// <exception cref="ProperExitException">
    /// For -h/--man/-V (exit code 0) and for any faulty parameter (exit code 2).
    /// </exception>
    public static Options Parse(string[] args)
    {
        var opts = new Options();

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            string? inlineValue = null;

            // Split "--name=value" into name and value.
            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                int equalsPosition = arg.IndexOf('=');
                if (equalsPosition > 0)
                {
                    inlineValue = arg[(equalsPosition + 1)..];
                    arg = arg[..equalsPosition];
                }
            }
            // Bundled flags like "-vvv" or "-nv": handle each letter on its own.
            else if (arg.Length > 2 && arg[0] == '-' && arg[1..].All(c => "vqn46".Contains(c)))
            {
                foreach (char flag in arg[1..])
                {
                    ApplyFlag(opts, "-" + flag);
                }
                continue;
            }

            // Fetches the value of an option which needs one: either the part
            // behind '=' or the next command line argument.
            string NextValue()
            {
                if (inlineValue != null)
                {
                    return inlineValue;
                }
                if (i + 1 >= args.Length)
                {
                    throw Fault($"Option {arg} requires an argument");
                }
                return args[++i];
            }

            switch (arg)
            {
                case "-h" or "--help":
                    throw new ProperExitException(ExitCode.AllOk, HelpText.Usage);
                case "--man":
                    throw new ProperExitException(ExitCode.AllOk, HelpText.Manual);
                case "-V" or "--version":
                    throw new ProperExitException(
                        ExitCode.AllOk,
                        $"ipxserver - version {Version}\n\n{HelpText.Usage}");

                case "-l" or "--log":
                    opts.LogFacility = (int)ParseNumber(arg, NextValue());
                    break;
                case "-p" or "--port":
                    opts.Port = (int)ParseNumber(arg, NextValue());
                    break;
                case "-P" or "--port6":
                    opts.Port6Option = (int)ParseNumber(arg, NextValue());
                    break;
                case "-u" or "--user":
                    opts.User = NextValue();
                    break;
                case "-i" or "--idle":
                    opts.Idle = ParseNumber(arg, NextValue());
                    break;
                case "-L" or "--logfile":
                    opts.LogFile = NextValue();
                    break;

                case "-v" or "-q" or "-n" or "--no-fork" or "-4" or "--ipv4-only"
                    or "-6" or "--ipv6-only":
                    if (inlineValue != null)
                    {
                        throw Fault($"Option {arg} does not take an argument");
                    }
                    ApplyFlag(opts, arg);
                    break;

                default:
                    throw Fault($"Unknown option: {args[i]}");
            }
        }

        opts.PerformParameterSanityCheck();
        return opts;
    }

    /// <summary>Handles all options which do not take a value.</summary>
    private static void ApplyFlag(Options opts, string flag)
    {
        switch (flag)
        {
            case "-v": opts.Verbose++; break;
            case "-q": opts.Quiet++; break;
            case "-n" or "--no-fork": opts.NoFork = true; break;
            case "-4" or "--ipv4-only": opts.Ipv4Only = true; break;
            case "-6" or "--ipv6-only": opts.Ipv6Only = true; break;
        }
    }

    /// <summary>Converts the value of a numeric option ("=i" in Getopt::Long).</summary>
    private static long ParseNumber(string option, string value)
    {
        if (!long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture,
                           out long number)
            || number is < int.MinValue or > int.MaxValue)
        {
            throw Fault($"Value \"{value}\" invalid for option {option} (number expected)");
        }
        return number;
    }

    /// <summary>
    /// Equivalent of perform_parameter_sanity_check() of the Perl version,
    /// extended by the checks for the new options.
    /// </summary>
    private void PerformParameterSanityCheck()
    {
        if (LogFacility is < 0 or >= 8)
        {
            throw new ProperExitException(
                ExitCode.CliParameterFault, "Invalid SYSLOG facility value (0 <= n < 8)");
        }
        if (Port is <= 0 or >= 65536)
        {
            throw new ProperExitException(
                ExitCode.CliParameterFault, "Invalid port number to listen on (0 < n < 65536)");
        }
        if (Port6 is <= 0 or >= 65536)
        {
            throw new ProperExitException(
                ExitCode.CliParameterFault,
                "Invalid IPv6 port number to listen on (0 < n < 65536)");
        }
        if (Ipv4Only && Ipv6Only)
        {
            throw new ProperExitException(
                ExitCode.CliParameterFault,
                "Options -4 and -6 exclude each other. Omit both to serve IPv4 and IPv6.");
        }
        if (Idle <= 0)
        {
            // The Perl version accepted nonsense here, which removed every
            // client at the first cleanup.
            throw new ProperExitException(
                ExitCode.CliParameterFault, "Invalid idle timeout (n > 0)");
        }
    }

    /// <summary>Builds the exception for a faulty command line (usage + exit code 2).</summary>
    private static ProperExitException Fault(string message) =>
        new(ExitCode.CliParameterFault, $"{message}\n\n{HelpText.Usage}");
}
