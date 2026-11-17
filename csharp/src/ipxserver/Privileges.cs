// ipxserver - standalone dosbox IPX server (C# port of perl/ipxserver.pl)
// See the copyright notice in Program.cs.

using System.Runtime.InteropServices;

namespace IpxServer;

/// <summary>
/// Dropping root privileges on Unix.
///
/// .NET has no managed API for this, but the functions of the C library can be
/// called directly (P/Invoke). That is safe to do in a .NET process although
/// it always has several threads: under Linux the kernel keeps the user id per
/// thread, but the setuid()/setgid() functions of the C library (glibc and
/// musl) apply the change to *all* threads of the process. It is important to
/// go through the C library for exactly this reason; a raw system call would
/// only change the calling thread.
/// </summary>
internal static partial class Privileges
{
    // The user and group ids are unsigned 32 bit numbers on all supported systems.
    [LibraryImport("libc")]
    private static partial uint getuid();

    [LibraryImport("libc")]
    private static partial uint geteuid();

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setuid(uint uid);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setgid(uint gid);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setgroups(nuint size, uint[]? list);

    /// <summary>Returns a pointer to a "struct passwd" or NULL, see getpwnam(3).</summary>
    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint getpwnam(string name);

    /// <summary>True if the process currently has root rights (real or effective).</summary>
    public static bool IsRoot =>
        !OperatingSystem.IsWindows() && (getuid() == 0 || geteuid() == 0);

    /// <summary>
    /// Equivalent of drop_root_privileges() of the Perl version: after creating
    /// the sockets and opening the log file, we no longer need to run as root.
    ///
    /// Does nothing if the process is not running as root or on Windows.
    ///
    /// Unlike the Perl version (where the lines were commented out) the group
    /// is changed as well: The process drops all supplementary groups and
    /// switches to the primary group of the user. Otherwise it would keep the
    /// file access rights of the group "root".
    /// </summary>
    /// <returns>
    /// Null on success (or if nothing was to be done), otherwise a description
    /// of what went wrong. In that case the process may still be root!
    /// </returns>
    public static string? DropRootPrivileges(string userName)
    {
        if (OperatingSystem.IsWindows() || !IsRoot)
        {
            return null;
        }

        // Look up the numeric ids of the user in /etc/passwd (or whatever the
        // system uses as user database).
        nint passwd = getpwnam(userName);
        if (passwd == 0)
        {
            return $"user '{userName}' not found";
        }
        // struct passwd starts with two pointers (pw_name, pw_passwd), followed
        // by pw_uid and pw_gid. This layout is the same for Linux (glibc and
        // musl), macOS and the BSDs.
        uint uid = (uint)Marshal.ReadInt32(passwd, 2 * nint.Size);
        uint gid = (uint)Marshal.ReadInt32(passwd, 2 * nint.Size + sizeof(uint));

        // The order matters: once the user id is changed, we are no longer
        // allowed to change the groups.
        if (setgroups(0, null) != 0)
        {
            return $"setgroups() failed: {Marshal.GetLastPInvokeErrorMessage()}";
        }
        if (setgid(gid) != 0)
        {
            return $"setgid({gid}) failed: {Marshal.GetLastPInvokeErrorMessage()}";
        }
        if (setuid(uid) != 0)
        {
            return $"setuid({uid}) failed: {Marshal.GetLastPInvokeErrorMessage()}";
        }

        // Paranoia: make sure there is no way back. setuid() as root also sets
        // the "saved user id", so this must fail now.
        if (uid != 0 && (setuid(0) == 0 || getuid() == 0 || geteuid() == 0))
        {
            return "privileges could be regained after dropping them";
        }
        return null;
    }
}
