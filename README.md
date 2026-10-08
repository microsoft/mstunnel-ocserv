# About

The OpenConnect VPN server (ocserv) is an open source Linux SSL
VPN server designed for organizations that require a remote access
VPN with enterprise user management and control. It follows
the [openconnect protocol](https://gitlab.com/openconnect/protocol)
and is the counterpart of the [openconnect VPN client](http://www.infradead.org/openconnect/).
It is also compatible with CISCO's AnyConnect SSL VPN.

The program consists of:
 1. ocserv, the main server application
 2. occtl, the server's control tool. A tool which allows one to query the
   server for information.
 3. ocpasswd, a tool to administer simple password files.


# Supported platforms

The OpenConnect VPN server is designed and tested to work, with both IPv6
and IPv4, on Linux systems. It is, however, known to work on FreeBSD,
OpenBSD and other BSD derived systems.

Known limitation is that on platforms, which do not support procfs(5),
changes to the configuration must only be made while ocserv(8) is stopped.
Not doing so will cause new worker processes picking up the new
configuration while ocserv-main will use the previous configuration.


# Build dependencies

## Debian/Ubuntu:
```
# Basic build tools
apt-get install -y build-essential meson ninja-build pkg-config
# Required
apt-get install -y libgnutls28-dev libev-dev libreadline-dev libtasn1-bin
# Optional functionality and testing
apt-get install -y libpam0g-dev liblz4-dev libseccomp-dev \
	libnl-route-3-dev libkrb5-dev libradcli-dev \
	libcurl4-gnutls-dev libcjose-dev libjansson-dev liboath-dev \
	libprotobuf-c-dev libtalloc-dev libllhttp-dev protobuf-c-compiler \
	gperf iperf3 lcov libuid-wrapper libpam-wrapper libnss-wrapper \
	libsocket-wrapper gss-ntlmssp haproxy iputils-ping freeradius \
	gawk gnutls-bin iproute2 jq tcpdump ipcalc faketime
# For manpages
apt-get install -y ronn
```

## Fedora/RHEL:
```
# Basic build tools
yum install -y meson ninja-build gcc pkgconf-pkg-config
# Required
yum install -y gnutls-devel libev-devel readline-devel libtasn1-tools
# Optional functionality and testing
yum install -y pam-devel lz4-devel libseccomp-devel \
	libnl3-devel krb5-devel radcli-devel libcurl-devel cjose-devel \
	jansson-devel liboath-devel protobuf-c-devel libtalloc-devel \
	llhttp-devel protobuf-c gperf iperf3 lcov uid_wrapper \
	pam_wrapper nss_wrapper socket_wrapper gssntlmssp haproxy iputils \
	freeradius gawk gnutls-utils iproute jq tcpdump faketime
# For manpages
yum install -y rubygem-ronn-ng
```

See [README-radius](doc/README-radius.md) for more information on Radius
dependencies and its configuration.

# Runtime dependencies

When the `restrict-user-to-routes` or `restrict-user-to-ports` options are
configured, ocserv invokes `/usr/libexec/ocserv-fw` at runtime to enforce
firewall rules. That script requires either `nft` (nftables) or `iptables`
depending on the backend selected with the `-Dfirewall-script=` meson option
at build time. The default is `nftables` when `nft` is present at configure
time, otherwise `iptables`.

# Build instructions

```
$ meson setup build
$ ninja -C build
$ meson test -C build
```

`meson setup build` configures the build into a `build/` subdirectory.
`ninja -C build` compiles. `meson test -C build` runs the test suite.

## Listing and changing build options

To see all available build options and their current values:
```
$ meson configure build
```

Before the build directory exists, you can also view the available options with:
```
$ meson setup --help
```

Options are set at configure time with `-D`:
```
$ meson setup build -Doidc-auth=enabled -Dlatency-stats=enabled
```

Or changed after the fact:
```
$ meson configure build -Doidc-auth=enabled
$ ninja -C build
```

Common options:

| Option                     | Default    | Description                              |
|----------------------------|------------|------------------------------------------|
| `-Doidc-auth=enabled`      | disabled   | OpenID Connect authentication            |
| `-Dlatency-stats=enabled`  | disabled   | Latency statistics gathering             |
| `-Dpam=disabled`           | auto       | PAM authentication                       |
| `-Dradius=disabled`        | auto       | RADIUS authentication/accounting         |
| `-Dgssapi=disabled`        | auto       | GSSAPI/Kerberos authentication           |
| `-Dseccomp=disabled`       | auto       | seccomp worker isolation                 |
| `-Dseccomp-trap=true`      | false      | Filtered syscalls fail with a signal     |
| `-Dkerberos-tests=true`    | false      | Enable Kerberos tests (requires KDC)     |
| `-Dwith-werror=true`       | false      | Treat compiler warnings as errors        |
| `-Db_coverage=true`        | false      | Enable gcov code coverage instrumentation|

## Code coverage

```
$ CFLAGS="-g -O0" meson setup build -Db_coverage=true
$ ninja -C build
$ meson test -C build
$ ninja -C build coverage
```

The HTML report is written to `build/meson-logs/coveragereport/index.html`.

## Building from git

Building from git requires the same tools as a release build. After cloning:
```
$ git submodule update --init
$ meson setup build
$ ninja -C build
```


# Basic installation instructions

Now you need to generate a certificate. E.g.
```
$ certtool --generate-privkey > ./test-key.pem
$ certtool --generate-self-signed --load-privkey test-key.pem --outfile test-cert.pem
```
(make sure you enable encryption or signing)


Create a dedicated user and group for the server unprivileged processes
(e.g., 'ocserv'), and then edit the [sample.config](doc/sample.config)
and set these users on run-as-user and run-as-group options. The run:
```
# cd doc && ../src/ocserv -f -c sample.config
```

# Configuration

Several configuration instruction are available in [the recipes repository](https://gitlab.com/openconnect/recipes).


# Profiling

To identify the bottlenecks in software under certain loads
you can profile ocserv using the following command.
```
# perf record -g ocserv
```

After the server is terminated, the output is placed in perf.data.
You may examine the output using:
```
# perf report
```


# Continuous Integration (CI)

We use the gitlab-ci continuous integration system. It is used to test
most of the Linux systems (see .gitlab-ci.yml),and is split in two phases,
build image creation and compilation/test. The build image creation is done
at the openconnect/build-images subproject and uploads the image at the gitlab.com
container registry. The compilation/test phase is on every commit to project.


# How the VPN works

Please see the [technical description page](http://ocserv.openconnect-vpn.net/technical.html).

# License

The license of ocserv is GPLv2+. See COPYING for the license terms.

Some individual code may be covered under other (compatible with
GPLv2) licenses. For the CCAN components see src/ccan/licenses/
The inih library is under the simplified BSD license (src/inih/LICENSE.txt).
