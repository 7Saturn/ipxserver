// ipxserver - standalone dosbox IPX server (C# port of perl/ipxserver.pl)
// See the copyright notice in Program.cs.

using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace IpxServer;

/// <summary>
/// The IPX server itself: the sockets, the list of registered clients and the
/// main loop. The methods correspond one to one to the functions of the Perl
/// version; their Perl names are given in the comments.
///
/// How it works, in short: dosbox wraps every IPX packet of the DOS program
/// unchanged into one UDP packet and sends it to this server. A client first
/// registers with a special packet and gets an IPX node address assigned.
/// From then on the server acts like a network switch: packets addressed to a
/// specific node are forwarded to that client only, broadcasts are forwarded
/// to everyone but the sender.
///
/// Threading: everything in here runs on the one thread which calls
/// <see cref="Run"/>, with the exception of the three Request...() methods.
/// Those only set a flag, which the main loop picks up at its next round, so
/// no locking is needed anywhere.
/// </summary>
internal sealed class Server : IDisposable
{
    /// <summary>
    /// Once every 10 minutes it's time to drop zombies and reinstate ignored hosts.
    /// </summary>
    internal const long CleanupInterval = 600;

    /// <summary>
    /// How long the main loop waits for a packet before it does a round
    /// without one, in microseconds (= 1 second). This is the central
    /// difference to the Perl version, whose recv() blocked until a packet (or
    /// signal) arrived, no matter how long that took.
    /// </summary>
    private const int ReceiveTimeoutMicroseconds = 1_000_000;

    /// <summary>
    /// Windows only: control code which stops Windows from reporting ICMP
    /// "port unreachable" answers to our sends as errors of the following
    /// receive call (see <see cref="OpenSocket"/>).
    /// </summary>
    private const int SioUdpConnReset = unchecked((int)0x9800000C);

    private readonly Options _opts;
    private readonly Log _log;

    /// <summary>The IPv4 socket, null if not (yet) open or disabled with -6.</summary>
    private Socket? _sock4;

    /// <summary>The IPv6 socket, null if not (yet) open or disabled with -4.</summary>
    private Socket? _sock6;

    /// <summary>
    /// Receive buffer. One byte more than the biggest acceptable packet, which
    /// allows us to detect packets that are too long.
    /// </summary>
    private readonly byte[] _buffer = new byte[Ipx.MaxPayloadSize + 1];

    /// <summary>Reused list for Socket.Select(), to avoid garbage in the main loop.</summary>
    private readonly List<Socket> _readable = new(2);

    /// <summary>
    /// The registered clients (%clients). Keys are the host identifiers, see
    /// <see cref="GetHostIdentifier"/>. For details see <see cref="Register"/>.
    /// </summary>
    private readonly Dictionary<string, Client> _clients = new();

    /// <summary>
    /// The bad guys (%ignore).
    /// Keys are IPs. Yes, we block entire IPs, not considering ports. A port
    /// switch is easily done and filtering for it, too, would just keep actual
    /// attackers. An IP switch is a lot more effort than just starting a new
    /// process.
    /// Values are the epoch time stamps when that particular IP was sent into
    /// the penalty box. Each IP remains there for at least the CleanupInterval.
    ///
    /// Note that (as in the Perl version) the penalty only suppresses repeated
    /// log messages, so that a troublemaker cannot flood the logs. Packets of
    /// such hosts are dropped for what is wrong with them, not because of this
    /// list; a host can still register properly while being listed here.
    /// </summary>
    private readonly Dictionary<string, long> _ignore = new();

    /// <summary>When do_cleanup() did its work the last time (a "state" variable in Perl).</summary>
    private long _cleanupDoneTime;

    // Set by the signal handlers (other threads), read by the main loop.
    private volatile bool _running = true;
    private volatile string? _shutdownReason;
    private volatile bool _disconnectAllRequested;
    private volatile bool _clientListRequested;

    /// <summary>
    /// The IPX node address of the server itself ($ipxSrvNode). As long as we
    /// are running, the port and address will not change. Like in the Perl
    /// version it is made of the bind address 0.0.0.0 and the (IPv4) port, e.g.
    /// 0000000000d5 for port 213. IPv4 and IPv6 clients see the same server
    /// node, as they all are in the same IPX network.
    /// </summary>
    public string IpxSrvNode { get; }

    /// <summary>The port the IPv4 socket is actually bound to (0 if there is none).</summary>
    public int BoundPort4 => (_sock4?.LocalEndPoint as IPEndPoint)?.Port ?? 0;

    /// <summary>The port the IPv6 socket is actually bound to (0 if there is none).</summary>
    public int BoundPort6 => (_sock6?.LocalEndPoint as IPEndPoint)?.Port ?? 0;

    /// <summary>Number of currently registered clients (for tests).</summary>
    internal int ClientCount => _clients.Count;

    public Server(Options opts, Log log)
    {
        _opts = opts;
        _log = log;
        _cleanupDoneTime = Now();

        int nodePort = opts.Ipv6Only ? opts.Port6 : opts.Port;
        IpxSrvNode = MakeNode(IPAddress.Any.GetAddressBytes(), nodePort);
    }

    /// <summary>
    /// Supplies the current time as epoch time stamp in seconds. Tests replace
    /// it to let time fly; do not touch it otherwise.
    /// </summary>
    internal Func<long> Clock { get; set; } = () => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    /// <summary>The current time as epoch time stamp in seconds (Perl: time).</summary>
    private long Now() => Clock();

    // ------------------------------------------------------------------
    // Sockets
    // ------------------------------------------------------------------

    /// <summary>
    /// Opens the IPv4 and/or IPv6 socket, depending on the options. This needs
    /// to happen before the root privileges are dropped, as ports below 1024
    /// are reserved for root on Unix.
    /// </summary>
    public void OpenSockets()
    {
        if (!_opts.Ipv6Only)
        {
            _sock4 = OpenSocket(AddressFamily.InterNetwork, _opts.Port);
        }
        if (!_opts.Ipv4Only)
        {
            if (Socket.OSSupportsIPv6)
            {
                _sock6 = OpenSocket(AddressFamily.InterNetworkV6, _opts.Port6);
            }
            else if (_opts.Ipv6Only)
            {
                Fatal(ExitCode.SocketFault,
                      "Could not open UDP socket: This system does not support IPv6.");
            }
            else
            {
                // IPv6 was not explicitly demanded, so IPv4 alone has to do.
                _log.Both(LogLevel.Warning,
                          "This system does not support IPv6. Serving IPv4 only.");
            }
        }
    }

    /// <summary>
    /// Equivalent of openSocket() of the Perl version: creates one UDP socket
    /// listening on all network interfaces.
    /// </summary>
    private Socket OpenSocket(AddressFamily family, int port)
    {
        bool isV6 = family == AddressFamily.InterNetworkV6;
        Socket? sock = null;
        try
        {
            sock = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            if (isV6)
            {
                // The IPv6 socket shall handle IPv6 only. Otherwise it would
                // (depending on the operating system's defaults) also claim the
                // IPv4 port of the same number, and the two sockets would get
                // in each other's way.
                sock.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
            }
            if (OperatingSystem.IsWindows())
            {
                // Windows peculiarity: If we send to a client which is gone and
                // its host answers with ICMP "port unreachable", the *next
                // receive* on this socket fails with "connection reset". This
                // switches that behaviour off.
                sock.IOControl(SioUdpConnReset, [0, 0, 0, 0], null);
            }
            // The decisive difference to the Perl version: nothing we do with
            // this socket is ever allowed to block.
            sock.Blocking = false;
            // We could use this at some point to tie the server to a specific
            // interface. We listen on any network card:
            sock.Bind(new IPEndPoint(isV6 ? IPAddress.IPv6Any : IPAddress.Any, port));
            return sock;
        }
        catch (SocketException e)
        {
            sock?.Dispose();
            string hint = e.SocketErrorCode == SocketError.AccessDenied && !OperatingSystem.IsWindows()
                ? " (ports below 1024 need special privileges, see README)"
                : "";
            string errorMessage =
                $"Could not open UDP socket for {(isV6 ? "IPv6" : "IPv4")} port {port}: {e.Message}{hint}";
            Fatal(ExitCode.SocketFault, errorMessage);
            throw; // Never reached, Fatal() always throws.
        }
    }

    /// <summary>Logs a fatal error to syslog and ends the program via proper_exit.</summary>
    private void Fatal(ExitCode code, string message)
    {
        _log.Syslog(LogLevel.Crit, message);
        // The log file entry is written by Program.Main ("Premature ending").
        throw new ProperExitException(code, message);
    }

    // ------------------------------------------------------------------
    // Main loop
    // ------------------------------------------------------------------

    /// <summary>
    /// The main loop. Returns after <see cref="RequestShutdown"/> was called.
    /// </summary>
    public void Run()
    {
        var sockets = new List<Socket>(2);
        if (_sock4 != null) sockets.Add(_sock4);
        if (_sock6 != null) sockets.Add(_sock6);
        if (sockets.Count == 0)
        {
            throw new InvalidOperationException("OpenSockets() must be called before Run().");
        }

        while (_running)
        {
            // Wait until at least one of the sockets has a packet for us, but
            // for one second at most. While waiting, the process is asleep
            // and uses no CPU time, which keeps the service very light-weight.
            // Select() removes all sockets from the list which have nothing to
            // read; after a timeout the list is empty.
            _readable.Clear();
            _readable.AddRange(sockets);
            try
            {
                Socket.Select(_readable, null, null, ReceiveTimeoutMicroseconds);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.Interrupted)
            {
                // A signal arrived while waiting. Treat it like a timeout.
                _readable.Clear();
            }

            // Signals are not handled in the signal handler itself but here,
            // i.e. within one second after they arrived.
            HandlePendingSignals();
            if (!_running)
            {
                break;
            }

            long ts = Now();
            // This is done in every round, with or without a packet. So,
            // unlike in the Perl version, zombies in the client list and
            // expired penalties are dealt with on time even if there is no
            // traffic at all.
            DoCleanup(ts);

            // Without a packet (timeout) this loop is simply skipped. If both
            // sockets have data, each one gets its turn. If there are more
            // packets waiting, Select() returns immediately in the next round.
            foreach (Socket sock in _readable)
            {
                ReceiveAndHandle(sock, ts);
            }
        }
    }

    /// <summary>
    /// Fetches one UDP packet from the given socket and processes it.
    /// </summary>
    private void ReceiveAndHandle(Socket sock, long ts)
    {
        // ReceiveFrom() wants an end point object of the matching address
        // family, which it then replaces by the sender's address.
        EndPoint remote = sock.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);
        int length;
        try
        {
            length = sock.ReceiveFrom(_buffer, SocketFlags.None, ref remote);
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.MessageSize)
        {
            // Windows reports packets bigger than the buffer this way, while
            // Linux silently cuts them off. Handle both alike below.
            length = _buffer.Length;
        }
        catch (SocketException e) when (e.SocketErrorCode
            is SocketError.WouldBlock      // someone else emptied the queue, cannot happen
            or SocketError.Interrupted     // signal
            or SocketError.ConnectionReset // Windows, see OpenSocket()
            or SocketError.NetworkReset)
        {
            return;
        }

        HandlePacket((IPEndPoint)remote, _buffer.AsSpan(0, length), ts);
    }

    /// <summary>
    /// Processes one received UDP packet. This is the body of the main loop of
    /// the Perl version.
    /// </summary>
    internal void HandlePacket(IPEndPoint src, ReadOnlySpan<byte> packet, long ts)
    {
        string srcaddr = src.Address.ToString();

        IpxDatagram? dgrm = IpxDecode(srcaddr, packet);
        if (dgrm == null)
        {
            return;
        }

        // Are they addressing us ourselves? Then we have to respond.
        bool needToRespond = dgrm.Dst.Node == IpxSrvNode
                             || dgrm.Dst.Node == Ipx.BroadcastNode;
        string srcIdentifier = GetHostIdentifier(src);
        // registration packet
        if (!needToRespond && dgrm.IsReg)
        {
            if (IsReRegistration(srcIdentifier))
            {
                return;
            }
            Register(ts, src);
            // After registration we have to respond, too.
            needToRespond = true;
        }
        else
        {
            if (IsUnregistered(srcIdentifier, srcaddr, ts))
            {
                return;
            }
            if (RevPathFilteringFailed(dgrm, srcIdentifier, srcaddr, ts))
            {
                return;
            }

            Client client = _clients[srcIdentifier];
            client.Ts = ts;
            client.TsC = ts;
            client.Sent += packet.Length;

            _log.Syslog(LogLevel.Debug,
                        $"[{srcIdentifier}] pkt {dgrm.Src.Node} > {dgrm.Dst.Node}");

            // This is actual payload communication, not just managing things.
            // We are acting as a switch, sending directed messages only to the
            // addressed recipient and broadcasts to anyone but the sender.
            foreach (string destIdentifier in GetDestinationIdentifiers(dgrm))
            {
                SockSend(packet, destIdentifier);
            }
        }

        if (needToRespond)
        {
            Respond(dgrm, srcIdentifier);
        }
    }

    // ------------------------------------------------------------------
    // Housekeeping
    // ------------------------------------------------------------------

    /// <summary>
    /// Equivalent of do_cleanup() of the Perl version. It is called in every
    /// round of the main loop, but only becomes active once per
    /// <see cref="CleanupInterval"/>: then it removes the clients which were
    /// idle for too long and lifts the penalties which have expired.
    /// </summary>
    internal void DoCleanup(long ts)
    {
        long maxTsWithoutCleanup = _cleanupDoneTime + CleanupInterval;
        // to simplify the code (and to reduce possible spoofed
        // disconnects), instead of listening for ICMP unreachables
        // we simply timeout the connections which we would have to
        // do anyway to mop up regularly disconnected users, as the
        // clients do not inform the server when they go away.
        long cleanupTimeout = ts - _opts.Idle;
        // The Perl version logged this as LOG_NOTICE "for debugging". As it
        // now really happens every ten minutes, it is a LOG_INFO here.
        _log.Syslog(LogLevel.Info,
                    $"Cleanup time {maxTsWithoutCleanup} exceeded. Cleaning up...");

        // ToList(): we must not remove entries while iterating the dictionary.
        foreach (string clientIdentifier in _clients.Keys.ToList())
        {
            if (_clients[clientIdentifier].Ts > cleanupTimeout)
            {
                continue;
            }
            string dataRate = GetDataRates(clientIdentifier);
            _log.Both(LogLevel.Notice,
                      $"[{clientIdentifier}] idle timeout reached, removing it ({dataRate}).");
            _clients.Remove(clientIdentifier);
        }

        // every interval we check what we can mop up
        List<string> reinstatedIps = _ignore
            .Where(entry => entry.Value + CleanupInterval < ts)
            .Select(entry => entry.Key)
            .ToList();
        foreach (string reinstatedIp in reinstatedIps)
        {
            _log.Both(LogLevel.Notice,
                      $"[{reinstatedIp}] Ignoring time exceeded, penalty is now lifted.");
            // (The Perl version had a bug here: it deleted $ignore{$_} instead
            // of $ignore{$reinstated_ip}, so penalties were never lifted.)
            _ignore.Remove(reinstatedIp);
        }
        _cleanupDoneTime = ts;
    }

    // ------------------------------------------------------------------
    // Checks on incoming packets
    // ------------------------------------------------------------------

    /// <summary>Equivalent of is_re_registration() of the Perl version.</summary>
    private bool IsReRegistration(string srcIdentifier)
    {
        // We *cannot* delete the previous registration. Nor can we ignore the guy.
        // Otherwise this gives an attacker the perfect means to effectively kick
        // other clients. The other (unlikely) cause is when the client OS (or NAT)
        // re-uses the same source port. So essentially we do nothing, but log it.
        if (_clients.ContainsKey(srcIdentifier))
        {
            _log.Both(LogLevel.Warning,
                      $"[{srcIdentifier}] re-registration, possibly spoofed DoS attempt");
            return true;
        }
        return false;
    }

    /// <summary>Equivalent of is_unregistered() of the Perl version.</summary>
    private bool IsUnregistered(string srcIdentifier, string srcaddr, long ts)
    {
        if (!_clients.ContainsKey(srcIdentifier))
        {
            if (!_ignore.ContainsKey(srcaddr))
            {
                _log.Both(LogLevel.Warning,
                          $"[{srcIdentifier}] packet(s) from unregistered source."
                          + $" Ignoring {srcaddr} for at least {CleanupInterval} seconds.");
            }
            _ignore[srcaddr] = ts;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Equivalent of rev_path_filtering_failed() of the Perl version: A client
    /// must use the node address we assigned to it as source address.
    /// Everything else is an attempt to send packets in the name of others.
    /// </summary>
    private bool RevPathFilteringFailed(IpxDatagram dgrm, string srcIdentifier,
                                        string srcaddr, long ts)
    {
        if (dgrm.Src.Node != _clients[srcIdentifier].Node)
        {
            if (!_ignore.ContainsKey(srcaddr))
            {
                _log.Both(LogLevel.Err,
                          $"[{srcIdentifier}] Reverse path filtering failure(s)."
                          + $" Ignoring {srcaddr} for at least {CleanupInterval} seconds.");
            }
            _ignore[srcaddr] = ts;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Equivalent of ipxDecode() of the Perl version: decodes a UDP payload
    /// into an IPX datagram and checks it for plausibility.
    /// </summary>
    /// <returns>The datagram, or null if the packet has to be dropped.</returns>
    internal IpxDatagram? IpxDecode(string srcaddr, ReadOnlySpan<byte> packet)
    {
        if (packet.Length < Ipx.HeaderLength)
        {
            _log.Syslog(LogLevel.Warning, $"[{srcaddr}] packet too short");
            return null;
        }
        if (packet.Length > Ipx.MaxPayloadSize)
        {
            // The Perl version cut such packets off at the maximum size, after
            // which they failed the length check below. Same result here.
            _log.Syslog(LogLevel.Warning, $"[{srcaddr}] packet too long");
            return null;
        }

        IpxDatagram dgrm = IpxDatagram.Unpack(packet);

        if (dgrm.Cksum != Ipx.ChecksumConst)
        {
            _log.Syslog(LogLevel.Warning, $"[{srcaddr}] cksum != 0xffff");
            return null;
        }
        if (dgrm.Len != Ipx.HeaderLength + dgrm.PayloadLength)
        {
            _log.Syslog(LogLevel.Warning, $"[{srcaddr}] length != header + payload");
            return null;
        }
        // We will not route IPX. So other networks are taboo.
        if (dgrm.Src.Net != Ipx.LocalNetwork)
        {
            _log.Syslog(LogLevel.Warning, $"[{srcaddr}] src not net zero traffic");
            return null;
        }
        if (dgrm.Dst.Net != Ipx.LocalNetwork)
        {
            _log.Syslog(LogLevel.Warning, $"[{srcaddr}] dst not net zero traffic");
            return null;
        }
        // HACK clause for the registration packets
        if (dgrm.Src.Node == dgrm.Dst.Node && !dgrm.IsReg)
        {
            // Otherwise the guy will spam the logs...
            if (!_ignore.ContainsKey(srcaddr))
            {
                _log.Both(LogLevel.Err,
                          $"[{srcaddr}] LAND attack packet received. Ignoring"
                          + $" {srcaddr} for at least {CleanupInterval} seconds.");
            }
            // Troublemakers will be ignored
            _ignore[srcaddr] = Now();
            return null;
        }

        return dgrm;
    }

    // ------------------------------------------------------------------
    // Registration, forwarding, responding
    // ------------------------------------------------------------------

    /// <summary>
    /// Equivalent of register() of the Perl version: adds a new client to the
    /// list and assigns its IPX node address.
    /// </summary>
    private void Register(long ts, IPEndPoint src)
    {
        // TODO connected bad guys can deduce the UDP src port and addr
        //	of other clients and spoof packets from them if there
        //	is no egress rpf at the end (or same subnet).  A fix
        //	for this would be to make the node addres a folded HMAC
        //	(however, although trivial, it might not be worth doing).
        //	If we end up doing this, it probably is safe to pay
        //	attention to those 'ICMP unreachable' messages that come
        //	back when we have a disconnected client
        string node = AssignNode(src);
        string srcIdentifier = GetHostIdentifier(src);
        _clients[srcIdentifier] = new Client
        {
            // A copy, so the entry is independent of the caller's object.
            EndPoint = new IPEndPoint(src.Address, src.Port),
            Node = node,
            Ts = ts,
            TsF = ts,
            TsC = ts,
        };
        _log.Both(LogLevel.Notice, $"[{src.Address}] registered client {node}");
    }

    /// <summary>
    /// Determines the IPX node address (6 bytes) for a new client.
    ///
    /// IPv4, exactly as in the Perl version: the 4 bytes of the IP address
    /// followed by the 2 bytes of the UDP port, e.g. 192.168.0.2:58619 becomes
    /// c0a80002e4fb. (rfc1234 does not seem to be completely NAT safe so we
    /// include the src port too, also makes 'ipxnet ping' pretty.)
    ///
    /// IPv6: The 16 bytes of an IPv6 address do not fit into an IPX node
    /// address. So the node is derived from a hash of address and port
    /// instead: the byte 0xfd followed by 5 bytes (40 bits) of the hash.
    /// The leading 0xfd guarantees that such a node can never be the same as
    /// the one of an IPv4 client, as IPv4 addresses starting with 253 are
    /// reserved and never appear as a sender. It also cannot be the broadcast,
    /// the registration or the server node. Should two IPv6 clients happen to
    /// get the same hash (1 : 2^40 per pair), the next free value is searched.
    /// The same client (address and port) gets the same node again when it
    /// re-connects later, just as IPv4 clients do.
    /// </summary>
    private string AssignNode(IPEndPoint src)
    {
        byte[] address = src.Address.GetAddressBytes();
        if (src.AddressFamily == AddressFamily.InterNetwork)
        {
            return MakeNode(address, src.Port);
        }

        // Input of the hash: address, scope (distinguishes equal link-local
        // addresses on different network interfaces), port and an attempt
        // counter for the collision handling.
        byte[] input = new byte[address.Length + sizeof(long) + sizeof(ushort) + 1];
        address.CopyTo(input, 0);
        BinaryPrimitives.WriteInt64BigEndian(input.AsSpan(address.Length), src.Address.ScopeId);
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(address.Length + sizeof(long)),
                                              (ushort)src.Port);
        Span<byte> hashBytes = stackalloc byte[sizeof(ulong)];
        for (int attempt = 0; ; attempt++)
        {
            input[^1] = (byte)attempt;
            BinaryPrimitives.WriteUInt64BigEndian(hashBytes, Fnv1a64(input));
            string node = "fd" + Convert.ToHexStringLower(hashBytes[..5]);
            if (!_clients.Values.Any(client => client.Node == node))
            {
                return node;
            }
        }
    }

    /// <summary>
    /// The 64 bit FNV-1a hash function, folded so that all input bits affect
    /// the upper bits we use. A simple, well distributing hash is all we need:
    /// The node address only has to be unique, it is not a secret (for IPv4
    /// it can be read off address and port directly). Doing it ourselves in
    /// these few lines keeps the program free of a dependency on OpenSSL,
    /// which .NET needs under Linux for its cryptographic hash functions.
    /// </summary>
    internal static ulong Fnv1a64(ReadOnlySpan<byte> data)
    {
        ulong hash = 14695981039346656037; // FNV offset basis
        foreach (byte b in data)
        {
            hash ^= b;
            hash *= 1099511628211;         // FNV prime
        }
        // Final mixing step (from MurmurHash3), as plain FNV leaves the upper
        // bits weakly mixed for inputs which differ only at the end.
        hash ^= hash >> 33;
        hash *= 0xff51afd7ed558ccd;
        hash ^= hash >> 33;
        return hash;
    }

    /// <summary>
    /// Builds a node address the classic way, from 4 address bytes and the
    /// port: unpack('H12', inet_aton($addr) . pack('n', $port)) in Perl.
    /// </summary>
    private static string MakeNode(byte[] ipv4Address, int port)
    {
        Span<byte> node = stackalloc byte[6];
        ipv4Address.CopyTo(node);
        BinaryPrimitives.WriteUInt16BigEndian(node[4..], (ushort)port);
        return Convert.ToHexStringLower(node);
    }

    /// <summary>
    /// Equivalent of get_destination_identifiers() of the Perl version:
    /// Who has to receive this datagram?
    /// </summary>
    private List<string> GetDestinationIdentifiers(IpxDatagram datagram)
    {
        return (datagram.Dst.Node == Ipx.BroadcastNode
                // Broadcasts go to everyone but the sender.
                ? _clients.Where(entry => entry.Value.Node != datagram.Src.Node)
                // Rest goes specifically where it is supposed to go.
                : _clients.Where(entry => entry.Value.Node == datagram.Dst.Node))
            .Select(entry => entry.Key)
            .ToList();
    }

    /// <summary>
    /// Equivalent of respond() of the Perl version: answers pings addressed to
    /// the server (or to everyone) and registrations.
    /// </summary>
    private void Respond(IpxDatagram dgrm, string srcIdentifier)
    {
        bool isPing = dgrm.Src.Sock == Ipx.ErrorHandlingPacket
                      && dgrm.Dst.Sock == Ipx.ErrorHandlingPacket;
        if (!isPing)
        {
            return;
        }
        // registration hack
        bool isRegistryCase = dgrm.Src.Node == Ipx.FakeNode;
        if (!isRegistryCase)
        {
            _log.Syslog(LogLevel.Info, $"[{srcIdentifier}] echo req from {dgrm.Src.Node}");
        }

        byte[] reply = IpxDatagram.BuildEchoReply(_clients[srcIdentifier].Node, IpxSrvNode);
        SockSend(reply, srcIdentifier);
    }

    /// <summary>
    /// Equivalent of sock_send() of the Perl version: sends a packet to a
    /// registered client, using the socket which matches the IP version of
    /// that client. So a packet received via IPv4 may well leave via IPv6.
    /// </summary>
    private void SockSend(ReadOnlySpan<byte> packet, string recipientIdentifier)
    {
        Client recipient = _clients[recipientIdentifier];
        Socket? sock = recipient.EndPoint.AddressFamily == AddressFamily.InterNetworkV6
            ? _sock6
            : _sock4;
        if (sock == null)
        {
            return; // Only possible in tests, which feed packets without sockets.
        }

        // TODO handle errors (mtu?) rather than just report them
        int sentCount;
        try
        {
            // The socket is non-blocking: if the send buffer of the operating
            // system is full, this fails right away instead of waiting.
            sentCount = sock.SendTo(packet, SocketFlags.None, recipient.EndPoint);
        }
        catch (SocketException e)
        {
            _log.Both(LogLevel.Err, $"[{recipientIdentifier}] unable to send: {e.Message}");
            return;
        }
        recipient.Received += sentCount;
        recipient.TsC = Now();

        if (sentCount != packet.Length)
        {
            _log.Both(LogLevel.Err, $"[{recipientIdentifier}] unable to send complete payload.");
        }
    }

    // ------------------------------------------------------------------
    // Signals
    // ------------------------------------------------------------------

    /// <summary>
    /// Asks the main loop to end (Perl: sigTERM). May be called from any thread.
    /// </summary>
    /// <param name="signalName">Name of the signal for the log, e.g. "TERM".</param>
    public void RequestShutdown(string signalName)
    {
        _shutdownReason ??= signalName;
    }

    /// <summary>
    /// Asks the main loop to disconnect all clients (Perl: sigHUP). May be
    /// called from any thread.
    /// </summary>
    public void RequestDisconnectAll() => _disconnectAllRequested = true;

    /// <summary>
    /// Asks the main loop to list all clients in the syslog (Perl: sigUSR1).
    /// May be called from any thread.
    /// </summary>
    public void RequestClientList() => _clientListRequested = true;

    /// <summary>
    /// Does the actual work for the signals which arrived since the last round
    /// of the main loop. This contains the bodies of the Perl signal handlers.
    /// </summary>
    private void HandlePendingSignals()
    {
        if (_disconnectAllRequested)
        {
            _disconnectAllRequested = false;
            _log.Both(LogLevel.Notice, "Caught SIGHUP, disconnecting all clients");
            _clients.Clear();
        }

        if (_clientListRequested)
        {
            _clientListRequested = false;
            _log.Both(LogLevel.Notice, "Caught SIGUSR1, listing all clients currently connected.");
            foreach (string identifier in _clients.Keys.Order(StringComparer.Ordinal))
            {
                string dataRate = GetDataRates(identifier);
                _log.Syslog(LogLevel.Notice, $"{identifier} is considered connected ({dataRate}).");
            }
            if (_clients.Count == 0)
            {
                _log.Syslog(LogLevel.Notice, "Currently no clients connected.");
            }
        }

        if (_shutdownReason != null && _running)
        {
            _log.Both(LogLevel.Notice, $"Caught SIG{_shutdownReason}...shutting down");
            _running = false;
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Equivalent of get_host_identifier() of the Perl version.
    /// For consistency reasons use this for creating an identifier. Maybe we
    /// will change that format of identifiers in the future. If so, you only
    /// need to alter this particular function. Not all occurences of
    /// identifiers...
    ///
    /// The format is "address:port" for IPv4 (e.g. 192.168.0.2:58619) and
    /// "[address]:port" for IPv6 (e.g. [2001:db8::2]:58619).
    /// </summary>
    internal static string GetHostIdentifier(IPEndPoint endPoint) => endPoint.ToString();

    /// <summary>
    /// Equivalent of get_data_rates() of the Perl version: describes the
    /// traffic of a client for the log.
    /// </summary>
    private string GetDataRates(string identifier)
    {
        Client client = _clients[identifier];
        long duration = client.TsC - client.TsF;
        if (duration == 0)
        {
            duration = 1;
        }
        double sentRate = (double)client.Sent / duration;
        double receivedRate = (double)client.Received / duration;
        return $"sent: {NumberFormat(client.Sent)}byte, {NumberFormat(sentRate)}byte/sec.;"
               + $" received: {NumberFormat(client.Received)}byte, {NumberFormat(receivedRate)}byte/sec.";
    }

    /// <summary>
    /// Equivalent of number_format() of the Perl version: 1234567 becomes
    /// "1.2 M", with one decimal place at most.
    /// </summary>
    internal static string NumberFormat(double number)
    {
        string[] prefixes = ["", "k", "M", "G", "T"];
        int index = 0;
        // (The Perl version ran beyond the list of prefixes for huge numbers.)
        while (number >= 1000 && index < prefixes.Length - 1)
        {
            number /= 1000;
            index++;
        }
        number = Math.Floor(number * 10 + 0.5) / 10;
        return $"{number.ToString("0.#", CultureInfo.InvariantCulture)} {prefixes[index]}";
    }

    /// <summary>Closes the sockets (Perl: $sock->close).</summary>
    public void Dispose()
    {
        _sock4?.Dispose();
        _sock4 = null;
        _sock6?.Dispose();
        _sock6 = null;
    }
}
