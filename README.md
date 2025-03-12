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
apt-get install -y build-essential pkg-config
# Required
apt-get install -y libgnutls28-dev libev-dev libreadline-dev
# Optional functionality and testing
apt-get install -y libpam0g-dev liblz4-dev libseccomp-dev \
	libnl-route-3-dev libkrb5-dev libradcli-dev \
	libcurl4-gnutls-dev libcjose-dev libjansson-dev liboath-dev \
	libprotobuf-c-dev libtalloc-dev libllhttp-dev protobuf-c-compiler \
	gperf iperf3 lcov libuid-wrapper libpam-wrapper libnss-wrapper \
	libsocket-wrapper gss-ntlmssp haproxy iputils-ping freeradius \
	gawk gnutls-bin iproute2 yajl-tools tcpdump
# For manpages
apt-get install -y ronn
```

## Fedora/RHEL:
```
# Basic build tools
yum install -y install make automake gcc pkgconf-pkg-config
# Required
yum install -y gnutls-devel libev-devel readline-devel
# Optional functionality and testing
yum install -y pam-devel lz4-devel libseccomp-devel \
	libnl3-devel krb5-devel radcli-devel libcurl-devel cjose-devel \
	jansson-devel liboath-devel protobuf-c-devel libtalloc-devel \
	llhttp-devel protobuf-c gperf iperf3 lcov uid_wrapper \
	pam_wrapper nss_wrapper socket_wrapper gssntlmssp haproxy iputils \
	freeradius gawk gnutls-utils iproute yajl tcpdump
# For manpages
yum install -y rubygem-ronn-ng
```

See [README-radius](doc/README-radius.md) for more information on Radius
dependencies and its configuration.

# Build instructions

To build from a distributed release use:

```
$ ./configure && make && make check
```

To test the code coverage of the test suite use the following:
```
$ ./configure --enable-code-coverage
$ make && make check && make code-coverage-capture
```

Note that the code coverage reported does not currently include tests which
are run within docker.

In addition to the prerequisites listed above, building from git requires
the following packages: autoconf, automake, and xz.

To build from the git repository use:
```
$ autoreconf -fvi
$ ./configure && make
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
