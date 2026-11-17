# ipxserver – C# port

A standalone IPX server for DOSBox (IPX tunnelled over UDP), ported from
[`perl/ipxserver.pl`](../perl/ipxserver.pl) to C# / .NET 10. It runs on Windows
and Linux from the same source code and is shipped as a single executable file
that needs no installed .NET runtime.

The port follows the Perl script function by function; every C# method names
its Perl counterpart in a comment. Two things were changed on purpose:

* **The main loop no longer blocks.** The Perl script waited in `recv()` until
  a packet arrived, however long that took, so idle clients and expired
  penalties were only dealt with when traffic happened to come in. The C#
  server waits for a packet for at most one second. If none arrives, it does a
  round without payload and only performs the housekeeping (idle sessions,
  penalty times, pending signals).
* **IPv4 and IPv6.** The server opens one UDP socket per IP version. The two
  ports can be chosen independently (`-p` and `-P`). All clients are in the
  same IPX network, so an IPv4 client and an IPv6 client can play together.

All other deviations are listed in [Differences to the Perl version](#differences-to-the-perl-version).

## Contents

1. [Repository layout](#repository-layout)
2. [Setting up the development environment](#setting-up-the-development-environment)
3. [Building](#building)
4. [Automatic releases with GitHub Actions](#automatic-releases-with-github-actions)
5. [Running the server](#running-the-server)
6. [Port 213 on Linux without running as root](#port-213-on-linux-without-running-as-root)
7. [Differences to the Perl version](#differences-to-the-perl-version)

## Repository layout

```
.github/workflows/ci.yml        build + tests on every push (Linux and Windows)
.github/workflows/release.yml   builds and publishes a release for every tag v*
.vscode/                        tasks, debugger and extension settings for VS Code
csharp/
  global.json                   pins the .NET SDK version (10.0.x)
  Directory.Build.props         settings shared by all projects, version number
  ipxserver.slnx                solution (server + tests)
  build.sh / build.ps1          build the release binaries for all platforms
  contrib/ipxserver.service     systemd unit
  src/ipxserver/                the server
    Program.cs                    start-up/shutdown sequence, signal handlers
    Options.cs                    command line options, exit codes
    HelpText.cs                   texts for --help and --man
    Log.cs                        log file and syslog
    Privileges.cs                 dropping root privileges (Unix)
    IpxDatagram.cs                IPX constants, packet decoding, client record
    Server.cs                     sockets, main loop, all of the server logic
  tests/ipxserver.Tests/        unit and integration tests
```

## Setting up the development environment

Three things are needed: Git, the **.NET 10 SDK**, and (optionally) Visual
Studio Code with the C# extension. No other tools, compilers or libraries are
required; cross-building for the other platforms works out of the box.

### Windows

In a terminal (PowerShell or cmd):

```
winget install Git.Git
winget install Microsoft.DotNet.SDK.10
winget install Microsoft.VisualStudioCode
```

Open a **new** terminal afterwards (so the changed `PATH` is picked up) and
check with `dotnet --version`; it must print `10.0.` followed by some number.

Without winget: download and run the installers from
<https://dotnet.microsoft.com/download/dotnet/10.0> (".NET SDK x64") and
<https://code.visualstudio.com>.

### Linux

Ubuntu 24.04 and newer have the SDK in their own package sources:

```
sudo apt update
sudo apt install git dotnet-sdk-10.0
```

Fedora: `sudo dnf install git dotnet-sdk-10.0`. For Debian and other
distributions see <https://learn.microsoft.com/dotnet/core/install/linux>; the
method which works everywhere, without root rights, is Microsoft's install
script:

```
curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0
echo 'export PATH="$HOME/.dotnet:$PATH"' >> ~/.bashrc    # then open a new shell
```

Check with `dotnet --version`. Visual Studio Code: `sudo snap install code --classic`
or the package from <https://code.visualstudio.com>.

### Visual Studio Code (both systems)

Open the **root folder of the repository** (not `csharp/`) in VS Code. It will
offer to install the recommended extension; accept, or install it by hand:

```
code --install-extension ms-dotnettools.csharp
```

Only this extension ("C#") is needed. It provides IntelliSense and the
debugger. The additional "C# Dev Kit" is not required.

The first build downloads a few packages from nuget.org, so internet access is
needed once.

## Building

### In Visual Studio Code

| Action | How |
| --- | --- |
| Build (debug) | `Ctrl+Shift+B` |
| Run in the debugger | `F5` — starts the server on the ports 2130 (IPv4) and 2131 (IPv6), so no special rights are needed |
| Run the tests | *Terminal → Run Task… → test* |
| Run without debugger | *Terminal → Run Task… → run* |
| Release binary for one platform | *Terminal → Run Task… → publish win-x64* / *publish linux-x64* / *publish linux-arm64* |
| Release binaries for all platforms | *Terminal → Run Task… → publish all* |

The tasks are defined in `.vscode/tasks.json`. Each one just calls the `dotnet`
command line shown in the next section.

### On the console

The commands are the same on Windows and Linux. Run them in the folder `csharp`.

```
dotnet build                                  # debug build of server and tests
dotnet run --project tests/ipxserver.Tests    # run the tests
dotnet run --project src/ipxserver -- -n -p 2130 -P 2131 -L ipxserver-debug.log
                                              # start the server from the sources
```

Release binaries (`-r` selects the target platform, any platform can be built
on any platform):

```
dotnet publish src/ipxserver -c Release -r win-x64     -o dist/win-x64
dotnet publish src/ipxserver -c Release -r linux-x64   -o dist/linux-x64
dotnet publish src/ipxserver -c Release -r linux-arm64 -o dist/linux-arm64
dotnet publish src/ipxserver -c Release -r linux-arm   -o dist/linux-arm
```

The result is one file, `dist/<platform>/ipxserver` (or `ipxserver.exe`), of
about 14 MB. It contains the .NET runtime; the target machine needs nothing
installed. Other platforms work the same way, e.g. `win-arm64` or
`linux-musl-x64` (Alpine Linux).

To build everything at once, including a test run first:

```
./build.sh                  # Linux
.\build.ps1                 # Windows (PowerShell)
```

`./build.sh --help` and `Get-Help .\build.ps1` list the options (version
number, selection of platforms). A Linux binary built on Windows loses its
"executable" flag on the way; run `chmod +x ipxserver` once on the Linux
machine.

### Tests

The tests are a plain console program without any test framework, so they
need nothing but the SDK. They contain unit tests and integration tests which
start a real server on the loopback interface and talk to it like DOSBox
clients, via IPv4 and IPv6 (the IPv6 test is skipped on machines without IPv6).
The exit code is 0 if everything passed.

### Version number

The version is defined in `csharp/Directory.Build.props` (`<Version>`) and can
be overridden per build with `-p:Version=2.1.0` (`build.sh --version 2.1.0`).
`ipxserver -V` prints it.

## Automatic releases with GitHub Actions

Two workflows are included; they need no configuration or secrets.

**`ci.yml`** builds the project and runs the tests on a Linux and a Windows
machine of GitHub, for every push to `master` and every pull request which
touches `csharp/`.

**`release.yml`** creates a release. To trigger it, push a tag consisting of a
`v` and the version number:

```
git tag v2.0.0
git push origin v2.0.0
```

On GitHub's servers the workflow then

1. installs the .NET SDK demanded by `csharp/global.json` (`actions/setup-dotnet`),
2. runs the tests on Linux and Windows,
3. runs `csharp/build.sh --package --version 2.0.0`, which builds the binaries
   for `win-x64`, `linux-x64`, `linux-arm64` and `linux-arm` and packs them
   (`.zip` for Windows, `.tar.gz` for Linux, each with this README; the Linux
   ones with the systemd unit as well),
4. creates the GitHub release `v2.0.0` and attaches the archives and a
   `SHA256SUMS.txt`.

The workflow can also be started by hand (*Actions → Release → Run workflow*).
In that case no release is created; the archives can be downloaded from the
page of the workflow run ("Artifacts") instead. This is handy for trying it
out.

Should the creation of the release fail with a permission error, check
*Settings → Actions → General → Workflow permissions* of the repository; the
workflow requests write access for itself, but an organisation policy can
forbid that.

## Running the server

Take the archive for the platform from the release page (or the file from
`dist/` after building) and unpack it. There is nothing to install.

```
ipxserver [options]
```

| Option | Meaning |
| --- | --- |
| `-p num`, `--port=num` | UDP port for IPv4 (default 213) |
| `-P num`, `--port6=num` | UDP port for IPv6 (default: same as `-p`) |
| `-4`, `--ipv4-only` | listen on IPv4 only |
| `-6`, `--ipv6-only` | listen on IPv6 only |
| `-i secs`, `--idle=secs` | remove clients which were idle for this long (default 1800) |
| `-L file`, `--logfile=file` | log file (default `/var/log/ipxserver.log`, Windows: `%ProgramData%\ipxserver\ipxserver.log`) |
| `-n`, `--no-fork` | additionally print the log messages to the terminal |
| `-v` / `-q` | more / less verbose, may be given several times |
| `-u user`, `--user=user` | Unix: user to switch to when started as root (default `nobody`) |
| `-l num`, `--log=num` | Unix: syslog facility `local0`…`local7` (default 0) |
| `-h`, `--man`, `-V` | help, manual, version |

A quick trial on any system, without special rights:

```
ipxserver -n -v -p 2130 -P 2131 -L ipxserver.log
```

In DOSBox (with `ipx=true` in the `[ipx]` section of its configuration) connect
with `IPXNET CONNECT <address of the server> 2130`. Without the port number
DOSBox uses 213. Note that DOSBox itself decides which IP version it uses; the
IPv6 socket of the server is of use for clients which can do IPv6.

**Logging.** Connects, disconnects and important events are always appended to
the log file. In addition, messages are sent to syslog, filtered by `-v`/`-q`.
On systems without syslog (Windows, containers) and with `-n` these messages
go to the terminal (stderr) instead.

**Exit codes.** 0 = regular end, 1 = a socket could not be opened, 2 = faulty
command line, 4 = log file could not be opened, 5 = log file could not be
written, 99 = unexpected internal error.

### Windows

1. Unpack `ipxserver.exe`, e.g. to `C:\Program Files\ipxserver`.
2. Allow the incoming UDP ports in the firewall (administrator terminal):

   ```
   netsh advfirewall firewall add rule name="ipxserver" dir=in action=allow protocol=UDP localport=213
   ```

3. Start it: `ipxserver.exe -n`. Windows has no restriction on ports below
   1024, so port 213 just works.

`Ctrl+C` stops the server, `Ctrl+Break` lists the connected clients. The
default log file is in `%ProgramData%\ipxserver`; if the account running the
server may not write there, choose another place with `--logfile`.

To start the server automatically with the system, one way is a scheduled
task (administrator terminal):

```
schtasks /Create /TN ipxserver /SC ONSTART /RU SYSTEM /TR "\"C:\Program Files\ipxserver\ipxserver.exe\""
```

### Linux

For a manual start, unpack the archive and run `./ipxserver -n -p 2130`. For
permanent operation use the included systemd unit, which also solves the port
question (next section):

```
sudo install -m 755 ipxserver /usr/local/bin/ipxserver
sudo install -m 644 ipxserver.service /etc/systemd/system/ipxserver.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipxserver
```

```
systemctl status ipxserver                 # is it running?
journalctl -u ipxserver -f                 # the syslog messages
sudo tail -f /var/log/ipxserver/ipxserver.log
sudo systemctl kill -s USR1 ipxserver      # list the connected clients in the journal
sudo systemctl kill -s HUP ipxserver       # disconnect all clients
sudo systemctl stop ipxserver
```

Options are added to the `ExecStart=` line of the unit. If a firewall is
active, open the UDP port(s), e.g. `sudo ufw allow 213/udp`.

Without systemd the signals are sent with `pkill -USR1 ipxserver`,
`pkill -HUP ipxserver` and `pkill ipxserver`. They take effect within one
second.

## Port 213 on Linux without running as root

On Linux only root may open ports below 1024. The standard port 213 is one of
them. There are several ways to use it without the server running as root
permanently. They are listed in the order of recommendation.

### 1. systemd grants the one needed privilege (recommended)

This is what `contrib/ipxserver.service` does. systemd starts the server as an
unprivileged user from the first moment and hands it exactly one capability,
`CAP_NET_BIND_SERVICE`:

```
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

The server is never root, not even during start-up.

### 2. Start as root, the server drops the privileges itself

This is the method of the Perl version, and it works in C# as well: .NET has
no API of its own for this, but the server calls the functions of the C
library directly (`setgroups`, `setgid`, `setuid`). When started as root, it
opens the log file and the sockets, then switches to the user given with `-u`
(default `nobody`) for good, and logs that it did so:

```
sudo ./ipxserver -u nobody
```

Unlike the Perl version it also leaves the group `root`. If switching fails
(e.g. the user does not exist), the server continues as root and writes a
warning to the logs, as the Perl version did.

### 3. Give the capability to the executable file

```
sudo setcap cap_net_bind_service=+ep /usr/local/bin/ipxserver
```

From then on every user may start this file with a port below 1024. This must
be repeated after every update of the file. It works with the single-file
binary only, not when starting via `dotnet ipxserver.dll`. As the user is not
root, the default log file in `/var/log` is not writable; pass `--logfile`.

### 4. Lower the limit for privileged ports

```
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=213
```

(permanent: put `net.ipv4.ip_unprivileged_port_start=213` into a file in
`/etc/sysctl.d/`). Despite the name the setting covers IPv6 as well. It allows
all users to use all ports from 213 on.

### 5. Listen on a high port and redirect

Run the server on an unprivileged port and let the packet filter redirect:

```
./ipxserver -p 2130 --logfile ~/ipxserver.log
sudo iptables  -t nat -A PREROUTING -p udp --dport 213 -j REDIRECT --to-ports 2130
sudo ip6tables -t nat -A PREROUTING -p udp --dport 213 -j REDIRECT --to-ports 2130
```

Or simply tell the clients the high port: `IPXNET CONNECT server 2130`.

## Differences to the Perl version

Functional changes requested for the port:

* Non-blocking main loop with a timeout of one second, see the top of this
  document. The cleanup itself still becomes active once per ten minutes
  (`CleanupInterval`), as before, but now on time and without the need for
  traffic. Signals are processed in the main loop, at most one second after
  they arrive.
* IPv6 support with the new options `-P`/`--port6`, `-4` and `-6`. If the
  system has no IPv6 at all, the server logs a warning and serves IPv4 only.
* IPX node addresses have six bytes. For IPv4 clients they are made of IP
  address and port, as before (`192.168.0.2:58619` → `c0a80002e4fb`). An IPv6
  address does not fit; IPv6 clients get `fd` followed by five bytes of a hash
  of address and port. Such a node can never collide with one of an IPv4
  client. In the logs IPv6 clients appear as `[address]:port`.

Changes caused by the platform:

* No fork into the background; a .NET process cannot do that. Use systemd (or
  the task scheduler on Windows). `-n` only means "also log to the terminal".
  Exit code 3 (fork failure) no longer occurs.
* New option `-L`/`--logfile`, because the fixed path `/var/log/ipxserver.log`
  exists neither on Windows nor is it writable for a non-root user.
* Syslog messages are sent to the socket `/dev/log` directly. If it does not
  exist, they go to stderr.
* The default port is the constant 213; `/etc/services` is not consulted.
* Signals on Windows: `Ctrl+C`, closing the console and system shutdown end
  the server; `Ctrl+Break` lists the clients. There is no equivalent of
  SIGHUP (disconnect all clients) on Windows.
* The version number is a normal `major.minor.patch` (starting with 2.0.0)
  instead of a date.

Small corrections:

* Lifting a penalty deleted the wrong hash key in Perl (`$ignore{$_}` instead
  of `$ignore{$reinstated_ip}`), so penalties were never lifted. Fixed.
* When dropping privileges the group is changed, too (was commented out).
* The periodic message "Cleanup time … exceeded" is logged at level INFO
  instead of NOTICE, as the comment in the Perl source intended. It would
  appear in the syslog every ten minutes otherwise.
* The start messages are written to the log file with `-n` as well, and two
  lines were added (listening ports, dropped privileges).
* Packets longer than 1452 bytes are logged as "packet too long" (Perl cut
  them off and then complained about the length field).
* An idle timeout of 0 or less is rejected.
* Flags may be bundled (`-vvv`).

Unchanged on purpose: the penalty list only throttles log messages, it does
not block hosts; an offending host can still register properly afterwards.

## Licence

GNU General Public License, version 2 or later, like the Perl original.
Copyright (C) 2010 Alexander Clouter.
