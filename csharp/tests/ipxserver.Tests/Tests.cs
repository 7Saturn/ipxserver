// Tests for ipxserver. See ipxserver.Tests.csproj for how to run them.
//
// There are two kinds of tests in here:
//  * unit tests of single functions (options, number formatting, ...)
//  * integration tests, which start a complete server on the loopback
//    interface and talk to it via UDP exactly like dosbox clients would do,
//    via IPv4 and (if the machine supports it) IPv6.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace IpxServer.Tests;

internal static class Tests
{
    // ------------------------------------------------------------------
    // Minimal test framework
    // ------------------------------------------------------------------

    private static int s_failed;

    private static int Main()
    {
        Run(nameof(OptionsDefaults), OptionsDefaults);
        Run(nameof(OptionsAllGiven), OptionsAllGiven);
        Run(nameof(OptionsFaults), OptionsFaults);
        Run(nameof(VerbosityLevel), VerbosityLevel);
        Run(nameof(NumberFormat), NumberFormat);
        Run(nameof(DatagramDecoding), DatagramDecoding);
        Run(nameof(Ipv6NodeAssignment), Ipv6NodeAssignment);
        Run(nameof(Ipv4Switching), Ipv4Switching);
        Run(nameof(BadPacketsAreDropped), BadPacketsAreDropped);
        Run(nameof(IdleLoopDoesCleanupWithoutTraffic), IdleLoopDoesCleanupWithoutTraffic);
        Run(nameof(SignalsAreHandledWithoutTraffic), SignalsAreHandledWithoutTraffic);
        Run(nameof(PortInUseIsSocketFault), PortInUseIsSocketFault);
        Run(nameof(Ipv6AndMixedSwitching), Ipv6AndMixedSwitching);

        Console.WriteLine(s_failed == 0 ? "\nAll tests passed." : $"\n{s_failed} test(s) FAILED.");
        return s_failed == 0 ? 0 : 1;
    }

    private sealed class SkipException(string reason) : Exception(reason);

    private static void Run(string name, Action test)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            test();
            Console.WriteLine($"[ ok ] {name} ({watch.ElapsedMilliseconds} ms)");
        }
        catch (SkipException e)
        {
            Console.WriteLine($"[skip] {name}: {e.Message}");
        }
        catch (Exception e)
        {
            s_failed++;
            Console.WriteLine($"[FAIL] {name}: {e}");
        }
    }

    private static void Check(bool condition, string what)
    {
        if (!condition)
        {
            throw new Exception($"Check failed: {what}");
        }
    }

    private static void Equal<T>(T expected, T actual, string what)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new Exception($"{what}: expected <{expected}>, got <{actual}>");
        }
    }

    private static ExitCode ExitCodeOf(Action action)
    {
        try
        {
            action();
        }
        catch (ProperExitException e)
        {
            return e.Code;
        }
        throw new Exception("Expected a ProperExitException, but there was none.");
    }

    // ------------------------------------------------------------------
    // Unit tests
    // ------------------------------------------------------------------

    private static void OptionsDefaults()
    {
        Options opts = Options.Parse([]);
        Equal(213, opts.Port, "default IPv4 port");
        Equal(213, opts.Port6, "default IPv6 port");
        Equal("nobody", opts.User, "default user");
        Equal(1800L, opts.Idle, "default idle");
        Equal(0, opts.LogFacility, "default facility");
        Check(!opts.NoFork && !opts.Ipv4Only && !opts.Ipv6Only, "flags off by default");

        // The IPv6 port follows the IPv4 port unless it is given explicitly.
        Equal(2130, Options.Parse(["-p", "2130"]).Port6, "IPv6 port follows -p");
    }

    private static void OptionsAllGiven()
    {
        Options opts = Options.Parse(
            ["-vv", "-q", "--port=1000", "-P", "2000", "--user", "ipx", "-i", "60",
             "-l", "7", "-n", "--logfile=/tmp/x.log", "-6"]);
        Equal(2, opts.Verbose, "-vv");
        Equal(1, opts.Quiet, "-q");
        Equal(1000, opts.Port, "--port");
        Equal(2000, opts.Port6, "-P");
        Equal("ipx", opts.User, "--user");
        Equal(60L, opts.Idle, "-i");
        Equal(7, opts.LogFacility, "-l");
        Equal("/tmp/x.log", opts.LogFile, "--logfile");
        Check(opts.NoFork && opts.Ipv6Only, "-n -6");
    }

    private static void OptionsFaults()
    {
        Equal(ExitCode.AllOk, ExitCodeOf(() => Options.Parse(["--help"])), "--help");
        Equal(ExitCode.AllOk, ExitCodeOf(() => Options.Parse(["-V"])), "-V");
        Equal(ExitCode.AllOk, ExitCodeOf(() => Options.Parse(["--man"])), "--man");
        string[][] faulty =
        [
            ["-p", "0"], ["-p", "65536"], ["-P", "0"], ["--port6=70000"], ["-l", "8"],
            ["-p"], ["-p", "abc"], ["--bogus"], ["-4", "-6"], ["-i", "0"], ["-x"],
            ["--no-fork=1"],
        ];
        foreach (string[] args in faulty)
        {
            Equal(ExitCode.CliParameterFault, ExitCodeOf(() => Options.Parse(args)),
                  string.Join(' ', args));
        }
    }

    private static void VerbosityLevel()
    {
        Equal(LogLevel.Notice, Log.GetSyslogVerbosityLevel(0, 0), "base level");
        Equal(LogLevel.Debug, Log.GetSyslogVerbosityLevel(2, 0), "-v -v");
        Equal(LogLevel.Debug, Log.GetSyslogVerbosityLevel(9, 0), "too verbose");
        Equal(LogLevel.Warning, Log.GetSyslogVerbosityLevel(1, 2), "-v -q -q");
        Equal(LogLevel.Emerg, Log.GetSyslogVerbosityLevel(0, 9), "too quiet");
    }

    private static void NumberFormat()
    {
        Equal("0 ", Server.NumberFormat(0), "0");
        Equal("999 ", Server.NumberFormat(999), "999");
        Equal("1 k", Server.NumberFormat(1000), "1000");
        Equal("1.2 M", Server.NumberFormat(1_234_567), "1234567");
        Equal("12.3 ", Server.NumberFormat(12.34), "12.34");
        Equal("2.5 T", Server.NumberFormat(2.5e12), "2.5e12");
        Equal("5000 T", Server.NumberFormat(5e15), "beyond the prefixes");
    }

    private static void DatagramDecoding()
    {
        byte[] packet = MakePacket("0a0000010203", 0x4002, "c0a80002e4fb", 0x4003, [1, 2, 3]);
        IpxDatagram dgrm = IpxDatagram.Unpack(packet);
        Equal((ushort)0xffff, dgrm.Cksum, "cksum");
        Equal((ushort)33, dgrm.Len, "len");
        Equal("0a0000010203", dgrm.Dst.Node, "dst node");
        Equal((ushort)0x4002, dgrm.Dst.Sock, "dst sock");
        Equal("c0a80002e4fb", dgrm.Src.Node, "src node");
        Equal((ushort)0x4003, dgrm.Src.Sock, "src sock");
        Equal("00000000", dgrm.Src.Net, "src net");
        Equal(3, dgrm.PayloadLength, "payload length");
        Check(!dgrm.IsReg, "data packet is no registration");
        Check(IpxDatagram.Unpack(RegistrationPacket()).IsReg, "registration is recognised");

        // The reply must decode to what was put in.
        IpxDatagram reply = IpxDatagram.Unpack(
            IpxDatagram.BuildEchoReply("c0a80002e4fb", "0000000000d5"));
        Equal("c0a80002e4fb", reply.Dst.Node, "reply dst");
        Equal("0000000000d5", reply.Src.Node, "reply src");
        Equal((ushort)30, reply.Len, "reply len");
        Equal((byte)2, reply.Type, "reply type");
    }

    /// <summary>
    /// The node assignment for IPv6 clients, tested without sockets so it also
    /// runs on machines without IPv6.
    /// </summary>
    private static void Ipv6NodeAssignment()
    {
        using var env = new TestServer(openSockets: false);
        var a = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 40000);
        var b = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 40001);
        var c = new IPEndPoint(IPAddress.Parse("192.168.0.2"), 58619);
        foreach (IPEndPoint endPoint in new[] { a, b, c })
        {
            env.Server.HandlePacket(endPoint, RegistrationPacket(), 1000);
        }
        Equal(3, env.Server.ClientCount, "three clients registered");
        Check(env.Logged("[192.168.0.2] registered client c0a80002e4fb"),
              "IPv4 node is address + port, as in the Perl version");

        List<string> v6Nodes = env.LogLines
            .Where(line => line.Contains("[2001:db8::1] registered client "))
            .Select(line => line[^12..])
            .ToList();
        Equal(2, v6Nodes.Count, "two IPv6 registrations logged");
        Check(v6Nodes.All(node => node.StartsWith("fd")), "IPv6 nodes start with fd");
        Check(v6Nodes[0] != v6Nodes[1], "different ports give different nodes");

        // A second registration from the same address and port is refused.
        env.Server.HandlePacket(a, RegistrationPacket(), 1001);
        Equal(3, env.Server.ClientCount, "re-registration does not add a client");
        Check(env.Logged("[[2001:db8::1]:40000] re-registration"), "re-registration is logged");
    }

    // ------------------------------------------------------------------
    // Integration tests
    // ------------------------------------------------------------------

    private static void Ipv4Switching()
    {
        using var env = new TestServer();
        using var a = new TestClient(env, AddressFamily.InterNetwork);
        using var b = new TestClient(env, AddressFamily.InterNetwork);
        using var c = new TestClient(env, AddressFamily.InterNetwork);
        a.Register();
        b.Register();
        c.Register();

        // 127.0.0.1 + port, e.g. 7f000001e4fb
        string expectedNode = "7f000001" + a.LocalPort.ToString("x4");
        Equal(expectedNode, a.Node, "IPv4 node address");
        Equal("00000000" + env.Server.BoundPort4.ToString("x4"), env.Server.IpxSrvNode, "server node");

        // Directed packet: only the addressee gets it.
        byte[] directed = MakePacket(b.Node, 0x4000, a.Node, 0x4000, [0xde, 0xad]);
        a.Send(directed);
        Check(directed.AsSpan().SequenceEqual(b.Receive()), "b receives the unchanged packet");
        Check(c.ReceiveNothing() && a.ReceiveNothing(), "nobody else receives it");

        // Broadcast: everyone but the sender gets it.
        byte[] broadcast = MakePacket(Ipx.BroadcastNode, 0x4000, a.Node, 0x4000, [1, 2, 3, 4]);
        a.Send(broadcast);
        Check(broadcast.AsSpan().SequenceEqual(b.Receive()), "b receives the broadcast");
        Check(broadcast.AsSpan().SequenceEqual(c.Receive()), "c receives the broadcast");
        Check(a.ReceiveNothing(), "the sender does not receive its own broadcast");

        // Ping to the server node: the server itself answers.
        a.Send(MakePacket(env.Server.IpxSrvNode, 2, a.Node, 2, []));
        IpxDatagram echo = IpxDatagram.Unpack(a.Receive());
        Equal(env.Server.IpxSrvNode, echo.Src.Node, "echo reply comes from the server node");
        Equal(a.Node, echo.Dst.Node, "echo reply goes to the client node");
        Check(b.ReceiveNothing() && c.ReceiveNothing(), "a ping to the server is not forwarded");
    }

    private static void BadPacketsAreDropped()
    {
        using var env = new TestServer();
        using var a = new TestClient(env, AddressFamily.InterNetwork);
        using var b = new TestClient(env, AddressFamily.InterNetwork);
        using var stranger = new TestClient(env, AddressFamily.InterNetwork);
        a.Register();
        b.Register();

        // Not registered.
        stranger.Send(MakePacket(b.Node, 0x4000, a.Node, 0x4000, [1]));
        Check(b.ReceiveNothing(), "packet from unregistered source is dropped");
        Check(env.Logged("packet(s) from unregistered source"), "unregistered source is logged");

        // Registered, but using the node address of somebody else as source.
        a.Send(MakePacket(Ipx.BroadcastNode, 0x4000, b.Node, 0x4000, [1]));
        Check(b.ReceiveNothing(), "spoofed source node is dropped");
        // 127.0.0.1 is in the penalty box already (stranger), so nothing is
        // logged again. That is the log throttling of the Perl version.
        Check(!env.Logged("Reverse path filtering"), "second offence of the same IP is not logged");

        // Too short, wrong checksum, wrong length field, foreign network.
        a.Send(new byte[10]);
        byte[] wrongChecksum = MakePacket(b.Node, 0x4000, a.Node, 0x4000, [1]);
        wrongChecksum[0] = 0;
        a.Send(wrongChecksum);
        byte[] wrongLength = MakePacket(b.Node, 0x4000, a.Node, 0x4000, [1]);
        wrongLength[3]++;
        a.Send(wrongLength);
        byte[] foreignNet = MakePacket(b.Node, 0x4000, a.Node, 0x4000, [1]);
        foreignNet[9] = 1;
        a.Send(foreignNet);
        // Bigger than an IPX packet may be.
        a.Send(MakePacket(b.Node, 0x4000, a.Node, 0x4000, new byte[Ipx.MaxPayloadSize]));
        // Source = destination ("LAND attack").
        a.Send(MakePacket(a.Node, 0x4000, a.Node, 0x4000, [1]));
        Check(b.ReceiveNothing() && a.ReceiveNothing(), "malformed packets are dropped");

        // The biggest allowed packet still passes, and the server still works.
        byte[] biggest = MakePacket(b.Node, 0x4000, a.Node, 0x4000,
                                    new byte[Ipx.MaxPayloadSize - Ipx.HeaderLength]);
        a.Send(biggest);
        Check(biggest.AsSpan().SequenceEqual(b.Receive()), "maximum size packet is forwarded");
    }

    /// <summary>
    /// The reason for this port to exist: the main loop must go round once per
    /// second and do its housekeeping even if no packet arrives at all.
    /// </summary>
    private static void IdleLoopDoesCleanupWithoutTraffic()
    {
        using var env = new TestServer(idle: 1800);
        using var a = new TestClient(env, AddressFamily.InterNetwork);
        using var stranger = new TestClient(env, AddressFamily.InterNetwork);
        a.Register();
        stranger.Send(MakePacket(a.Node, 0x4000, a.Node, 0x4001, [1])); // earns a penalty
        Check(a.ReceiveNothing(), "packet from the stranger is dropped");
        Equal(1, env.Server.ClientCount, "one client registered");

        // Not yet idle for long enough: the client stays.
        env.TimeOffset = 1700;
        Thread.Sleep(1500);
        Equal(1, env.Server.ClientCount, "client is kept before the idle timeout");

        // Let time fly beyond the idle timeout. From now on NOT A SINGLE packet
        // is sent, the server has to notice on its own.
        env.TimeOffset = 4000;
        var watch = Stopwatch.StartNew();
        while (env.Server.ClientCount != 0 && watch.ElapsedMilliseconds < 5000)
        {
            Thread.Sleep(50);
        }
        Equal(0, env.Server.ClientCount, "idle client is removed without any traffic");
        Check(watch.ElapsedMilliseconds < 2000,
              $"removal happens within the 1 s timeout (took {watch.ElapsedMilliseconds} ms)");
        Check(env.Logged("idle timeout reached, removing it"), "removal is logged");
        Check(env.Logged("[127.0.0.1] Ignoring time exceeded, penalty is now lifted."),
              "penalty is lifted without any traffic");
    }

    private static void SignalsAreHandledWithoutTraffic()
    {
        using var env = new TestServer();
        using var a = new TestClient(env, AddressFamily.InterNetwork);
        a.Register();

        env.Server.RequestClientList();
        Thread.Sleep(1500);
        Check(env.Logged($"127.0.0.1:{a.LocalPort} is considered connected"), "USR1 lists the client");

        env.Server.RequestDisconnectAll();
        Thread.Sleep(1500);
        Equal(0, env.Server.ClientCount, "HUP disconnects all clients");

        var watch = Stopwatch.StartNew();
        env.Server.RequestShutdown("TERM");
        Check(env.WaitForExit(3000), "TERM ends the main loop");
        Check(watch.ElapsedMilliseconds < 2000, "shutdown happens within the 1 s timeout");
        Check(env.Logged("Caught SIGTERM...shutting down"), "shutdown is logged");
    }

    private static void PortInUseIsSocketFault()
    {
        using var blocker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        blocker.Bind(new IPEndPoint(IPAddress.Any, 0));
        int port = ((IPEndPoint)blocker.LocalEndPoint!).Port;
        Equal(ExitCode.SocketFault,
              ExitCodeOf(() => new TestServer(port4: port, ipv4Only: true).Dispose()),
              "port in use");
    }

    private static void Ipv6AndMixedSwitching()
    {
        if (!Socket.OSSupportsIPv6)
        {
            throw new SkipException("this machine does not support IPv6");
        }
        using var env = new TestServer();
        Check(env.Server.BoundPort6 != 0, "IPv6 socket is open");
        Check(env.Server.BoundPort4 != env.Server.BoundPort6,
              "IPv4 and IPv6 use different ports in this test");

        using var v4 = new TestClient(env, AddressFamily.InterNetwork);
        using var v6a = new TestClient(env, AddressFamily.InterNetworkV6);
        using var v6b = new TestClient(env, AddressFamily.InterNetworkV6);
        v4.Register();
        v6a.Register();
        v6b.Register();
        Check(v6a.Node.StartsWith("fd") && v6b.Node.StartsWith("fd"), "IPv6 nodes start with fd");
        Check(v6a.Node != v6b.Node, "IPv6 nodes are unique");

        // IPv6 -> IPv6
        byte[] packet = MakePacket(v6b.Node, 0x4000, v6a.Node, 0x4000, [6, 6]);
        v6a.Send(packet);
        Check(packet.AsSpan().SequenceEqual(v6b.Receive()), "IPv6 to IPv6");
        // IPv6 -> IPv4
        packet = MakePacket(v4.Node, 0x4000, v6a.Node, 0x4000, [6, 4]);
        v6a.Send(packet);
        Check(packet.AsSpan().SequenceEqual(v4.Receive()), "IPv6 to IPv4");
        // IPv4 -> IPv6
        packet = MakePacket(v6b.Node, 0x4000, v4.Node, 0x4000, [4, 6]);
        v4.Send(packet);
        Check(packet.AsSpan().SequenceEqual(v6b.Receive()), "IPv4 to IPv6");
        Check(v6a.ReceiveNothing(), "directed packets do not go astray");
        // Broadcast from IPv4 reaches both IPv6 clients.
        packet = MakePacket(Ipx.BroadcastNode, 0x4000, v4.Node, 0x4000, [0xff]);
        v4.Send(packet);
        Check(packet.AsSpan().SequenceEqual(v6a.Receive()), "broadcast reaches first IPv6 client");
        Check(packet.AsSpan().SequenceEqual(v6b.Receive()), "broadcast reaches second IPv6 client");
        Check(v4.ReceiveNothing(), "sender does not get its own broadcast");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// <summary>Builds an IPX packet (network numbers are always 0).</summary>
    private static byte[] MakePacket(string dstNode, ushort dstSock, string srcNode, ushort srcSock,
                                     byte[] payload)
    {
        byte[] packet = new byte[Ipx.HeaderLength + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(packet, 0xffff);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        Convert.FromHexString(dstNode).CopyTo(packet, 10);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(16), dstSock);
        Convert.FromHexString(srcNode).CopyTo(packet, 22);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(28), srcSock);
        payload.CopyTo(packet, Ipx.HeaderLength);
        return packet;
    }

    /// <summary>The packet dosbox sends for "IPXNET CONNECT".</summary>
    private static byte[] RegistrationPacket() => MakePacket(Ipx.FakeNode, 2, Ipx.FakeNode, 2, []);

    /// <summary>Finds a UDP port which is free right now.</summary>
    private static int FreePort(AddressFamily family)
    {
        using var probe = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        probe.Bind(new IPEndPoint(
            family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    /// <summary>
    /// A complete server running on its own thread, with a temporary log file
    /// and a clock the test can move forward.
    /// </summary>
    private sealed class TestServer : IDisposable
    {
        private readonly string _logFile = Path.Combine(
            Path.GetTempPath(), $"ipxserver-test-{Guid.NewGuid():N}.log");
        private readonly Log _log;
        private readonly Thread? _thread;
        private readonly List<string> _syslogLines = [];

        public Server Server { get; }

        /// <summary>Seconds added to the real time, as seen by the server.</summary>
        public long TimeOffset
        {
            get => Interlocked.Read(ref _timeOffset);
            set => Interlocked.Exchange(ref _timeOffset, value);
        }
        private long _timeOffset;

        public TestServer(bool openSockets = true, long idle = 1800, int? port4 = null,
                          bool ipv4Only = false)
        {
            var opts = new Options
            {
                Port = port4 ?? FreePort(AddressFamily.InterNetwork),
                Idle = idle,
                Ipv4Only = ipv4Only,
            };
            if (Socket.OSSupportsIPv6 && !ipv4Only)
            {
                opts.Port6Option = FreePort(AddressFamily.InterNetworkV6);
            }
            _log = new Log(_logFile, 0, verbose: 2, quiet: 0, logToStderr: false, useSyslog: false)
            {
                SyslogObserver = (_, message) =>
                {
                    lock (_syslogLines)
                    {
                        _syslogLines.Add(message);
                    }
                },
            };
            Server = new Server(opts, _log);
            Server.Clock = () => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + TimeOffset;
            if (!openSockets)
            {
                return;
            }
            try
            {
                Server.OpenSockets();
            }
            catch
            {
                Dispose();
                throw;
            }
            _thread = new Thread(Server.Run) { IsBackground = true, Name = "ipxserver main loop" };
            _thread.Start();
        }

        /// <summary>Everything logged so far (syslog channel, which is a superset here).</summary>
        public List<string> LogLines
        {
            get
            {
                lock (_syslogLines)
                {
                    return [.. _syslogLines];
                }
            }
        }

        public bool Logged(string part) => LogLines.Any(line => line.Contains(part));

        public bool WaitForExit(int milliseconds) => _thread == null || _thread.Join(milliseconds);

        public void Dispose()
        {
            Server.RequestShutdown("TERM");
            _thread?.Join(5000);
            Server.Dispose();
            _log.Dispose();
            File.Delete(_logFile);
        }
    }

    /// <summary>Plays the role of a dosbox instance connected to the server.</summary>
    private sealed class TestClient : IDisposable
    {
        private readonly Socket _socket;
        private readonly IPEndPoint _server;

        /// <summary>The IPX node address the server assigned at registration.</summary>
        public string Node { get; private set; } = "";

        public int LocalPort => ((IPEndPoint)_socket.LocalEndPoint!).Port;

        public TestClient(TestServer env, AddressFamily family)
        {
            bool isV6 = family == AddressFamily.InterNetworkV6;
            _socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(new IPEndPoint(isV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
            _server = isV6
                ? new IPEndPoint(IPAddress.IPv6Loopback, env.Server.BoundPort6)
                : new IPEndPoint(IPAddress.Loopback, env.Server.BoundPort4);
        }

        public void Send(byte[] packet) => _socket.SendTo(packet, _server);

        /// <summary>Waits up to 3 seconds for a packet from the server.</summary>
        public byte[] Receive()
        {
            if (!_socket.Poll(TimeSpan.FromSeconds(3), SelectMode.SelectRead))
            {
                throw new Exception("Expected a packet from the server, but none arrived.");
            }
            byte[] buffer = new byte[2000];
            int length = _socket.Receive(buffer);
            return buffer[..length];
        }

        /// <summary>True if no packet arrives within a short while.</summary>
        public bool ReceiveNothing() => !_socket.Poll(TimeSpan.FromMilliseconds(300), SelectMode.SelectRead);

        /// <summary>Registers with the server like dosbox does and remembers the assigned node.</summary>
        public void Register()
        {
            Send(RegistrationPacket());
            IpxDatagram reply = IpxDatagram.Unpack(Receive());
            Node = reply.Dst.Node;
        }

        public void Dispose() => _socket.Dispose();
    }
}
