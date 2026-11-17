// ipxserver - standalone dosbox IPX server (C# port of perl/ipxserver.pl)
// See the copyright notice in Program.cs.

using System.Buffers.Binary;
using System.Net;

namespace IpxServer;

/// <summary>
/// Constants of the IPX protocol and of the IPX-over-UDP tunnelling as dosbox
/// does it. Node addresses and network numbers are handled as lower case hex
/// strings, exactly like in the Perl version (unpack 'H12' / 'H8'). That makes
/// them directly usable in log messages.
/// </summary>
internal static class Ipx
{
    /// <summary>This is a fixed definition by the IPX protocol.</summary>
    public const int HeaderLength = 30;

    /// <summary>Everyone is addressed, meaning, even we will respond to those calls.</summary>
    public const string BroadcastNode = "ffffffffffff";

    /// <summary>The IPX pendant to Ping has this type.</summary>
    public const byte EchoProtocolPacket = 2;

    /// <summary>Pings and registrations use this socket.</summary>
    public const ushort ErrorHandlingPacket = 2;

    /// <summary>IPX does not calculate checksums, so this is always constant.</summary>
    public const ushort ChecksumConst = 0xffff;

    /// <summary>
    /// We will not work with IPX routers. So the network communicated with
    /// must be the local one.
    /// </summary>
    public const string LocalNetwork = "00000000";

    /// <summary>And there will be no hops for routing necessary.</summary>
    public const byte MaxHopCount = 0;

    /// <summary>IPX packet cannot be bigger than 1500(MTU) - 40(IP) - 8(UDP).</summary>
    public const int MaxPayloadSize = 1452;

    /// <summary>
    /// Registration uses fake source and destination nodes. If we receive
    /// those via UDP, then it's an attempt to register with us.
    /// </summary>
    public const string FakeNode = "000000000000";
}

/// <summary>One of the two addresses (source or destination) of an IPX header.</summary>
/// <param name="Net">Network number, 8 hex digits.</param>
/// <param name="Node">Node address, 12 hex digits.</param>
/// <param name="Sock">IPX socket number.</param>
internal readonly record struct IpxAddress(string Net, string Node, ushort Sock);

/// <summary>
/// A decoded IPX packet. Equivalent of the <c>%dgrm</c> hash of the Perl
/// version.
///
/// Layout of the IPX header (all numbers big endian), in Perl's notation
/// 'nnCCH8H12nH8H12na*':
/// <code>
///   offset  size  content
///        0     2  checksum (always 0xffff)
///        2     2  packet length including this header
///        4     1  hop count ("transport control")
///        5     1  packet type
///        6     4  destination network
///       10     6  destination node
///       16     2  destination socket
///       18     4  source network
///       22     6  source node
///       28     2  source socket
///       30     *  payload
/// </code>
/// </summary>
internal sealed class IpxDatagram
{
    public ushort Cksum { get; private init; }
    public ushort Len { get; private init; }
    public byte HopCount { get; private init; }
    public byte Type { get; private init; }
    public IpxAddress Dst { get; private init; }
    public IpxAddress Src { get; private init; }
    public int PayloadLength { get; private init; }

    /// <summary>
    /// Splits the raw bytes into the header fields (the "unpack" part of
    /// ipxDecode() of the Perl version). The caller has to make sure the packet
    /// has at least <see cref="Ipx.HeaderLength"/> bytes. No plausibility
    /// checks are done here, see <see cref="Server.IpxDecode"/> for those.
    /// </summary>
    public static IpxDatagram Unpack(ReadOnlySpan<byte> packet) => new()
    {
        Cksum = BinaryPrimitives.ReadUInt16BigEndian(packet),
        Len = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]),
        HopCount = packet[4],
        Type = packet[5],
        Dst = new IpxAddress(
            Net: Convert.ToHexStringLower(packet.Slice(6, 4)),
            Node: Convert.ToHexStringLower(packet.Slice(10, 6)),
            Sock: BinaryPrimitives.ReadUInt16BigEndian(packet[16..])),
        Src = new IpxAddress(
            Net: Convert.ToHexStringLower(packet.Slice(18, 4)),
            Node: Convert.ToHexStringLower(packet.Slice(22, 6)),
            Sock: BinaryPrimitives.ReadUInt16BigEndian(packet[28..])),
        PayloadLength = packet.Length - Ipx.HeaderLength,
    };

    /// <summary>
    /// Equivalent of isReg() of the Perl version: Is this the packet a dosbox
    /// client sends to register with the server ("IPXNET CONNECT")?
    /// </summary>
    public bool IsReg =>
        // we ignore 'type' as it seems that:
        //  * dosbox 0.72 => type = (not initialised - garbage)
        //  * dosbox 0.73 => type = 0
        HopCount == Ipx.MaxHopCount
        && Len == Ipx.HeaderLength
        && Src.Net == Dst.Net
        && Src.Net == Ipx.LocalNetwork
        && Src.Node == Dst.Node
        && Src.Node == Ipx.FakeNode
        && Src.Sock == Dst.Sock
        && Src.Sock == Ipx.ErrorHandlingPacket;

    /// <summary>
    /// Builds the echo reply which answers pings and registrations (the "pack"
    /// in respond() of the Perl version). It is a bare IPX header without
    /// payload, sent from the server node to the given client node. A freshly
    /// registered client learns its own node address from the destination
    /// field of this packet.
    /// </summary>
    public static byte[] BuildEchoReply(string clientNode, string serverNode)
    {
        byte[] reply = new byte[Ipx.HeaderLength];
        Span<byte> span = reply;
        BinaryPrimitives.WriteUInt16BigEndian(span, Ipx.ChecksumConst);
        BinaryPrimitives.WriteUInt16BigEndian(span[2..], Ipx.HeaderLength);
        span[4] = Ipx.MaxHopCount;
        span[5] = Ipx.EchoProtocolPacket;
        Convert.FromHexString(Ipx.LocalNetwork).CopyTo(span[6..]);
        Convert.FromHexString(clientNode).CopyTo(span[10..]);
        BinaryPrimitives.WriteUInt16BigEndian(span[16..], Ipx.ErrorHandlingPacket);
        Convert.FromHexString(Ipx.LocalNetwork).CopyTo(span[18..]);
        Convert.FromHexString(serverNode).CopyTo(span[22..]);
        BinaryPrimitives.WriteUInt16BigEndian(span[28..], Ipx.ErrorHandlingPacket);
        return reply;
    }
}

/// <summary>
/// Everything the server knows about a registered client. Equivalent of the
/// anonymous hash created in register() of the Perl version. All time stamps
/// are epoch times (seconds).
/// </summary>
internal sealed class Client
{
    /// <summary>IP address and UDP port of the client, e.g. 192.168.0.2:58619 or [2001:db8::2]:58619.</summary>
    public required IPEndPoint EndPoint { get; init; }

    /// <summary>The IPX node address assigned to the client, e.g. c0a80002e4fb.</summary>
    public required string Node { get; init; }

    /// <summary>Last time this client has sent data.</summary>
    public long Ts { get; set; }

    /// <summary>First time this client has communicated.</summary>
    public long TsF { get; init; }

    /// <summary>Last time this client has communicated.</summary>
    public long TsC { get; set; }

    /// <summary>Number of bytes this client has sent so far.</summary>
    public long Sent { get; set; }

    /// <summary>Number of bytes this client has received so far.</summary>
    public long Received { get; set; }
}
