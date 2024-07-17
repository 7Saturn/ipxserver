#!/usr/bin/perl
# Found at http://stuff.digriz.org.uk/ipxserver
# See copyright at the end.

=head1 NAME

ipxserver - standalone dosbox IPX server

=head1 DESCRIPTION

B<ipxserver> provides an alternative to the built in dosbox
IPXNET server that can be run on any UNIX box that has Perl
installed.  The main advantages being that it runs standalone
and if run as root it can listen on port 213/udp (the IANA
assigned port for IPX over IP tunnelling).

=cut

use strict;
use warnings;

use Getopt::Long qw/:config no_ignore_case/;
use Pod::Usage;
use File::Basename;
use Sys::Syslog qw/:standard :macros/;
use POSIX qw/setsid/;
use Socket;
use IO::Socket::INET;
use feature 'signatures';
no warnings qw(experimental::signatures);
use Readonly;

#use Data::Dumper;

my $VERSION = '20100124';

Readonly my %error_code =>
    (
     all_ok              => 0,
     socket_fault        => 1,
     cli_parameter_fault => 2,
     fork_failure        => 3,
    );

sub proper_exit ($error_code, $message = undef) {
    if (defined $message) {
        if ($error_code{all_ok} != $error_code) {
            say STDERR $message;
        }
        else {
            say STDOUT $message;
        }
    }
    exit $error_code;
}

Readonly my @DEBUG => (
    LOG_EMERG,   # system is unusable
    LOG_ALERT,   # action must be taken immediately
    LOG_CRIT,    # critical conditions
    LOG_ERR,     # error conditions
    LOG_WARNING, # warning conditions
    LOG_NOTICE,  # normal, but significant, condition, see $base_verbosity
    LOG_INFO,    # informational message
    LOG_DEBUG    # verbose-level message
);

Readonly my $base_verbosity => 5;
Readonly my $cleanup_interval => 600;

#This is a fixed definition by the IPX protocol:
Readonly my $ipx_header_length => 30;
# Everyone is addressed, meaning, even we will respond to those calls:
Readonly my $ipx_broadcast_node => 'ffffffffffff';
# The IPX pendant to Ping has this type:
Readonly my $echo_protocol_packet => 2;
# Pings and registrations use this socket:
Readonly my $error_handling_packet => 2;
# IPX does not calculate checksums, so this is always constant:
Readonly my $ipx_checksum_const => 0xffff;
# We will not work with IPX routers.
# So the network communicated with must be the local one:
Readonly my $ipx_local_network => '00000000';
# And there will be not hops for routing necessary.
Readonly my $max_hop_count => 0;
# IPX packet cannot be bigger than 1500(MTU) - 40(IP) - 8(UDP)
Readonly my $max_ipx_payload_size => 1452;
# Registration uses fake source and destination nodes. If we receive those via
# UDP, then it's an attempt to register with us:
Readonly my $fake_node => '000000000000';

=head1 OPTIONS

=over 4

=item B<-h, --help>

Print a brief help message and exits.

=item B<--man>

Print complete manpage and exits.

=item B<-V, --version>

Print version number and exit.

=item B<-v>

Make more verbose (state multiple '-v's for more verbosity).

=item B<-q>

Make more quiet (state multiple '-q's for less verbosity).

=item B<-l num, --log=num>

Set the syslog local facility (default '0'), valid values
range from 0 to 7 inclusively.

=item B<-p num, --port=num>

Set UDP port to listen on (default 213), values below 1024
require this program to be run as root.

=item B<-u user, --user=user>

If running as root then after opening UDP port drop privileges
to unprivileged user account (default 'nobody').

=item B<-i secs, --idle=secs>

As there is no concept of disconnecting with IPXNET we have to
idle out the connections instead.  With this you can set the
timeout value (default 1800).

=item B<-n, --no-fork>

Do not fork the program as a daemon, and additionally logs to
STDERR.

=back

=cut

my $port = getservbyname('ipx', 'udp') || 213;
my %opts = (
	v	=> 0,
	q	=> 0,

	l	=> 0,
	p	=> $port,
	u	=> 'nobody',
	i	=> 1800,
);
GetOptions(
    'h|help'    => sub { pod2usage(-exitval => $error_code{all_ok}) },
    'man'       => sub { pod2usage(-exitval => $error_code{all_ok},
                                   -verbose => 2) },
    'V|version' => sub { pod2usage(-exitval => $error_code{all_ok},
                                   -message => "ipxserver - version $VERSION\n") },

    'v+'        => \$opts{v},
    'q+'        => \$opts{q},

    'l|log=i'   => \$opts{l},
    'p|port=i'  => \$opts{p},
    'u|user=s'  => \$opts{u},
    'i|idle=i'  => \$opts{i},

    'n|no-fork' => \$opts{n},
) || pod2usage($error_code{cli_parameter_fault});


unless ($opts{l} >= 0 && $opts{l} < 8) {
    proper_exit($error_code{cli_parameter_fault},
                'Invalid SYSLOG facility value (0 <= n < 8)');
}
unless ($opts{p} > 0 && $opts{p} < 65536) {
    proper_exit($error_code{cli_parameter_fault},
                'Invalid port number to listen on (0 < n < 65536)');
}

if (defined $opts{n}) {
	openlog(basename($0), 'ndelay|pid|perror', "local$opts{l}");
}
else {
	# perlfaq8 - How do I fork a daemon process?
	my $sid = setsid;
	chdir '/';

	open STDIN,  '+>/dev/null';
	open STDOUT, '+>&STDIN';
	open STDERR, '+>&STDIN';

	my $pid = fork;
    unless (defined $pid) {
        proper_exit($error_code{fork_failure},
                    "Unable to fork() as daemon: $!");
    }
    if ($pid != 0) {
        proper_exit($error_code{all_ok});
    }

	openlog(basename($0), 'ndelay|pid', "local$opts{l}");

	syslog LOG_NOTICE, 'started';
}

if ($base_verbosity + $opts{v} - $opts{q} >= scalar(@DEBUG)) {
	setlogmask(LOG_UPTO(LOG_DEBUG));
}
elsif ($base_verbosity + $opts{v} - $opts{q} < 0) {
	setlogmask(LOG_UPTO(LOG_EMERG));
}
else {
	setlogmask(LOG_UPTO($DEBUG[$base_verbosity + $opts{v} - $opts{q}]));
}

my $sock = &openSocket();

# lets make 'ps'/'netstat' look prettier
$0 = basename($0);

# After creating the socket, we no longer need to run as root
if ($< == 0 || $> == 0) {
	$< = $> = getpwnam $opts{u};
	syslog LOG_WARNING, "Unable to drop root uid priv: $!"
		if ($!);
}
#if ($( == 0 || $) == 0) {
#	$( = $) = getgrnam $opts{u};
#	syslog LOG_WARNING, "unable to drop root gid priv: $!"
#		if ($!);
#}

# the server address does not really matter, so we pick 0.0.0.0
# as it is impossible that anything else would use this
# --> Actually it means listening on all network interfaces with IPv4...
# We could use this at some point to tie the server to a specific interface.
# As long as we are running, the port and address will not change...
Readonly my $ipxSrvNode => unpack('H12', inet_aton('0.0.0.0') . pack('n', $opts{p}));

my (%clients, %ignore);
my $running = 1;
my $cleanup_done_time = time;

$SIG{INT}=$SIG{TERM}=\&sigTERM;
$SIG{HUP}=\&sigHUP;
$SIG{USR1}=\&sigUSR1;

while ($running) {
    # This is blocking. So unless we have traffic, this service will basically
    # not use up any CPU time, making it very light-weight.
	my $srcpaddr = $sock->recv(my $payload, $max_ipx_payload_size, 0);

	# if there has been a signal, this is undef
	next unless ($srcpaddr);

	my $ts = time;
    if ($cleanup_done_time + $cleanup_interval < $ts) {
		# to simplify the code (and to reduce possible spoofed
		# disconnects), instead of listening for ICMP unreachables
		# we simply timeout the connections which we would have to
		# do anyway to mop up regularly disconnected users, as the
		# clients do not inform the server when they go away.
        my $cleanup_timeout = $ts - $opts{i};
        foreach my $client_identifier (keys %clients) {
			next if $clients{$client_identifier}{ts} > $cleanup_timeout;

			syslog LOG_NOTICE, "[$clients{$client_identifier}{ip}] idle timeout for $clients{$client_identifier}{node}";
			delete $clients{$client_identifier};
		}

		# every interval we check what we can mop up
		delete $ignore{$_}
			for grep { $ignore{$_} + $cleanup_interval < $ts } keys %ignore;

		$cleanup_done_time = $ts;
	}

	my ($srcport, $srciaddr) = sockaddr_in $srcpaddr;
	my $srcaddr = inet_ntoa $srciaddr;

	my $dgrm = &ipxDecode($srcaddr, $payload);
	next unless defined $dgrm;

    # Are they addressing us ourselves?
    my $respond = (   $dgrm->{dst}{node} eq $ipxSrvNode
                   || $dgrm->{dst}{node} eq $ipx_broadcast_node);
	my $src_identifier = get_node_identifier($srcaddr, $srcport);
	# registration packet
	if (!$respond && isReg($dgrm)) {
		# we *cannot* delete the previous registeration otherwise
		# this gives bad users a perfect opportunity to effectively
		# kick others off.  The other, although unlikely, cause is
		# if the client OS (or NAT) re-uses the same source port.
		if (exists $clients{$src_identifier}) {
			syslog LOG_WARNING, "[$srcaddr] re-registration, possibly spoofed DoS attempt";
			next;
		}

		&register(\%clients, $ts, $srcaddr, $srcport);
        # After registration we have to respond, too.
		$respond = 1;
	}
	else {
		unless (exists $clients{$src_identifier}) {
            unless (defined $ignore{$srcaddr}) {
                syslog LOG_WARNING, "[$srcaddr] packet(s) from unregistered source";
            }
			$ignore{$srcaddr} = $ts;
			next;
		}

		# reverse path filtering
		unless ($dgrm->{src}{node} eq $clients{$src_identifier}{node}) {
            unless (defined $ignore{$srcaddr}) {
                syslog LOG_ERR, "[$srcaddr] reverse path filtering failure(s)";
            }
			$ignore{$srcaddr} = $ts;
			next;
		}

		$clients{$src_identifier}{ts} = $ts;

		syslog LOG_DEBUG, "[$srcaddr] pkt $dgrm->{src}{node} > $dgrm->{dst}{node}";

		my $destination_identifiers = get_destination_identifiers($dgrm);

		# N.B. we do not increment transport control as really
		#	we are acting as a switch
		# TODO handle errors (mtu?) rather than just report them
		foreach my $dest_identifier (@$destination_identifiers) {
			my $n = $sock->send($payload,
                                MSG_DONTWAIT,
                                $clients{$dest_identifier}{paddr});
			unless (defined $n) {
				syslog LOG_ERR, "[$clients{$dest_identifier}{ip}] unable to sendto()";
				next;
			}
			unless ($n == length($payload)) {
				syslog LOG_ERR, "[$clients{$dest_identifier}{ip}] unable to sendto() complete payload";
				next;
			}
		}
	}

	next unless ($respond);

    my $is_ping = (   $dgrm->{src}{sock} == $error_handling_packet
                   && $dgrm->{dst}{sock} == $error_handling_packet);
	if ($is_ping) {
		# registration hack
        unless ($dgrm->{src}{node} eq $fake_node) {
            syslog LOG_INFO, "[$srcaddr] echo req from $dgrm->{src}{node}";
        }

		my $reply = pack 'nnCCH8H12nH8H12na*',
			$ipx_checksum_const, $ipx_header_length,              $max_hop_count, $echo_protocol_packet,
			$ipx_local_network,  $clients{$src_identifier}{node}, $error_handling_packet,
			$ipx_local_network,  $ipxSrvNode,                     $error_handling_packet;

		# N.B. we do not check that the whole packet has been sent,
		#	as we have bigger problems if we cannot send a
		#	30 byte payload
		# TODO handle errors (mtu?) rather than just report them
		my $n = $sock->send($reply,
                            MSG_DONTWAIT,
                            $clients{$src_identifier}{paddr});
		unless (defined $n) {
			syslog LOG_ERR, "[$srcaddr] unable to sendto()";
			next;
		}
	}
}

$sock->close;

syslog LOG_NOTICE, 'exited';

proper_exit($error_code{all_ok});

sub get_destination_identifiers ($datagram) {
    my @client_identifiers = keys %clients;
    my @destination_identifiers =
        ($datagram->{dst}{node} eq $ipx_broadcast_node)
        # Broadcasts go to everyone but the sender.
        ? grep { $clients{$_}{node} ne $datagram->{src}{node} } @client_identifiers
        # Rest goes specifically where it is supposed to go.
        : grep { $clients{$_}{node} eq $datagram->{dst}{node} } @client_identifiers;
    return \@destination_identifiers;
}

sub sigTERM {
	my $signal = shift;

	if ($running) {
		syslog LOG_NOTICE, "caught SIG$signal...shutting down";
		$running = 0;
	}
};
sub sigHUP {
	my $signal = shift;

	syslog LOG_NOTICE, "caught SIGHUP, disconnecting all clients";
	%clients = ();
}

sub sigUSR1 {
	my $signal = shift;
	syslog LOG_NOTICE, "caught SIGUSR1, listing all clients currently connected.";
    my @client_identifiers = sort keys %clients;
    my $counter = @client_identifiers;
    foreach my $identifier (@client_identifiers) {
        syslog LOG_NOTICE, "$identifier is considered connected.";
    }
    unless (@client_identifiers) {
        syslog LOG_NOTICE, "Currently no clients connected.";
    }
}

sub openSocket () {
	my %args = (
		LocalPort	=> $opts{p},
		Proto		=> 'udp'
	);

    # as dosbox is not v6 enabled... :-/
    #	eval {
    #		require Socket6;
    #		require IO::Socket::INET6;
    #	};
    #	my $sock = ($@)
    #		? IO::Socket::INET->new(%args)
    #		: IO::Socket::INET6->new(%args);
	my $sock = IO::Socket::INET->new(%args);
    unless (defined $sock) {
        my $error_message = "Could not open UDP socket: $!";
        syslog LOG_CRIT, $error_message;
        proper_exit($error_code{socket_fault},
                    $error_message);
    }

	return $sock;
}

sub ipxDecode ($srcaddr, $packet) {
	if (length($packet) < $ipx_header_length) {
		syslog LOG_WARNING, "[$srcaddr] packet too short";
		return undef;
	}

	my %dgrm;
    ($dgrm{cksum},    $dgrm{len},       $dgrm{hop_count}, $dgrm{type},
     $dgrm{dst}{net}, $dgrm{dst}{node}, $dgrm{dst}{sock},
     $dgrm{src}{net}, $dgrm{src}{node}, $dgrm{src}{sock},
     $dgrm{payload})
        = unpack 'nnCCH8H12nH8H12na*', $packet;

	unless (defined $dgrm{payload}) {
		syslog LOG_WARNING, "[$srcaddr] unable to unpack() packet";
		return;
	}

	unless ($dgrm{cksum} == $ipx_checksum_const) {
		syslog LOG_WARNING, "[$srcaddr] cksum != 0xffff";
		return;
	}
	unless ($dgrm{len} == $ipx_header_length + length($dgrm{payload})) {
		syslog LOG_WARNING, "[$srcaddr] length != header + payload";
		return;
	}
    # We will not route IPX. So other networks are taboo.
	unless ($dgrm{src}{net} eq $ipx_local_network) {
		syslog LOG_WARNING, "[$srcaddr] src not net zero traffic";
		return;
	}
	unless ($dgrm{dst}{net} eq $ipx_local_network) {
		syslog LOG_WARNING, "[$srcaddr] dst not net zero traffic";
		return;
	}
	# HACK clause for the registration packets
	if ($dgrm{src}{node} eq $dgrm{dst}{node} && !isReg(\%dgrm)) {
		syslog LOG_ERR, "[$srcaddr] LAND attack packet";
        # Troublemakers will be ignored for the $cleanup_interval
        $ignore{$srcaddr} = time;
		return;
	}

	return \%dgrm;
}

sub isReg ($d) {
	# we ignore 'type' as it seems that:
	#  * dosbox 0.72 => type = (not initialised - garbage)
	#  * dosbox 0.73 => type = 0
    return (   $d->{hop_count} == $max_hop_count
            && $d->{len}       == $ipx_header_length
            && $d->{src}{net}  eq $d->{dst}{net}
            && $d->{src}{net}  eq $ipx_local_network
            && $d->{src}{node} eq $d->{dst}{node}
            && $d->{src}{node} eq $fake_node
            && $d->{src}{sock} == $d->{dst}{sock}
            && $d->{src}{sock} == $error_handling_packet);
}

sub register ($clients, $ts, $srcaddr, $srcport) {
	# rfc1234 does not seem to be completely NAT safe so we
	# include the src port too, also makes 'ipxnet ping' pretty
	my $node = unpack('H12', inet_aton($srcaddr) . pack('n', $srcport));
	my $paddr = sockaddr_in $srcport, inet_aton($srcaddr);

	# TODO connected bad guys can deduce the UDP src port and addr
	#	of other clients and spoof packets from them if there
	#	is no egress rpf at the end (or same subnet).  A fix
	#	for this would be to make the node addres a folded HMAC
	#	(however, although trivial, it might not be worth doing).
	#	If we end up doing this, it probably is safe to pay
	#	attention to those 'ICMP unreachable' messages that come
	#	back when we have a disconnected client
	my $src_identifier = get_node_identifier($srcaddr, $srcport);
	$clients->{$src_identifier} = {
        ip    => $srcaddr,
        port  => $srcport,
        node  => $node,
        paddr => $paddr,
        ts	  => $ts, # Time stamp when this client has sent the last time
	};

	syslog LOG_NOTICE, "[$srcaddr] registered client $node";
}

# For consistency reasons use this for creating an identifier. Maybe we will
# change that format of identifiers in the future. If so, you only need to alter
# this particular function. Not all occurences of identifiers...
sub get_node_identifier ($addr, $port) {
    return "$addr:$port";
}

__END__

=head1 SYNOPSIS

ipxserver [options]

=over 4

=item disconnect all clients

pkill -HUP ipxserver

=item shutdown

pkill ipxserver

=back

=head1 ERROR CODES

=over 4

=item 0

Everything went fine, normal operations until normal shutdown.

=item 1

Could not open socket. Usually that means either there is not network interface
with IPv4 active or the UDP port meant to be used is already used by another
process.

=item 2

Command line parameter faulty. This means, the provided CLI parameters are
somehow wrong/unusable.

=item 3

Fork failure: The child process could not be spawned. Usually that means
something external is wrong, e.g. not enough RAM left to duplicate the process.

=back

=head1 CHANGELOG

=over 4

=item B<20100123>

First version conceived.

=item B<20100124>

Removed the '$d{hop_count} == 0' sanity check, GTA trips on this.
Added a logging throttling mechanism for unknown hosts and
RPF failures.

=back

=head1 SEE ALSO

It is worth going over to L<http://www.dosbox.com/wiki/IPX> to
read up about IPX networking with dosbox.

=head1 COPYRIGHT

ipxserver - standalone dosbox IPX server

Copyright (C) 2010 Alexander Clouter <alex@digriz.org.uk>.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

=cut
