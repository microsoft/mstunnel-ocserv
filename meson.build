project('ocserv', 'c',
  version: '1.5.0',
  license: 'GPL-2.0-or-later',
  meson_version: '>= 0.53.0',
  default_options: ['c_std=c99', 'warning_level=2'],
)

cc = meson.get_compiler('c')
fs = import('fs')

# --------------------------------------------------------------------------
# Compiler flags
# --------------------------------------------------------------------------

warn_flags = cc.get_supported_arguments([
  '-Wno-strict-aliasing',
  '-Wno-unused-parameter',
  '-Wno-sign-compare',
  '-Wno-missing-field-initializers',
  '-Wno-implicit-fallthrough',
  '-Wno-stringop-truncation',
])
if get_option('with-werror')
  warn_flags += ['-Werror']
endif
add_project_arguments(warn_flags, language: 'c')

# _GNU_SOURCE and friends (AC_USE_SYSTEM_EXTENSIONS)
add_project_arguments('-D_GNU_SOURCE', language: 'c')

# When building with coverage instrumentation, define WITH_COVERAGE so that
# worker processes can explicitly flush gcov data before calling _exit().
if get_option('b_coverage')
  add_project_arguments('-DWITH_COVERAGE', language: 'c')
endif

# --------------------------------------------------------------------------
# Required tools
# --------------------------------------------------------------------------

gperf  = find_program('gperf', required: false)
protoc = find_program(['protoc', 'protoc-c'], required: false)
ipcalc = find_program(['ipcalc', 'ipcalc-ng'], required: false)

# Firewall script selection
_fw_opt = get_option('firewall-script')
fw_script_type = (_fw_opt == 'auto') ? 'nftables' : _fw_opt
message('firewall script: ' + fw_script_type)

# --------------------------------------------------------------------------
# Required dependencies
# --------------------------------------------------------------------------

gnutls_dep  = dependency('gnutls',  version: '>= 3.3.5')
nettle_dep  = dependency('nettle',  version: '>= 2.7')
libev_dep   = cc.find_library('ev', required: true)

# --------------------------------------------------------------------------
# Optional dependencies
# --------------------------------------------------------------------------

opt_pam     = get_option('pam')
opt_radius  = get_option('radius')
opt_gssapi  = get_option('gssapi')
opt_liboath = get_option('liboath')
opt_libnl   = get_option('libnl')
opt_maxmind = get_option('maxmind')
opt_geoip   = get_option('geoip')
opt_lz4     = get_option('lz4')
opt_seccomp = get_option('seccomp')
opt_systemd = get_option('systemd')
opt_oidc    = get_option('oidc-auth')
opt_utmp    = get_option('utmp')
opt_wrap    = get_option('libwrap')

# talloc: system or bundled
talloc_dep = dependency('', required: false)
if not get_option('local-talloc')
  talloc_dep = dependency('talloc', required: false)
  if not talloc_dep.found()
    talloc_dep = cc.find_library('talloc', required: false)
  endif
endif
use_local_talloc = not talloc_dep.found()

# llhttp: system or bundled
llhttp_dep = dependency('', required: false)
if not get_option('local-llhttp')
  llhttp_dep = cc.find_library('llhttp',
    has_headers: ['llhttp.h'], required: false)
endif
use_local_llhttp = not llhttp_dep.found()

# protobuf-c: system or bundled
protobuf_dep = dependency('', required: false)
if not get_option('local-protobuf')
  protobuf_dep = dependency('libprotobuf-c', required: false)
  if not protobuf_dep.found()
    protobuf_dep = cc.find_library('protobuf-c',
      has_headers: ['protobuf-c/protobuf-c.h'], required: false)
  endif
endif
use_local_protobuf = not protobuf_dep.found()

# PAM
pam_dep = dependency('', required: false)
if not opt_pam.disabled()
  pam_dep = cc.find_library('pam',
    has_headers: ['security/pam_appl.h'],
    required: opt_pam)
endif

# RADIUS: try radcli first, then freeradius-client
radcli_dep = dependency('', required: false)
legacy_radius = false
if not opt_radius.disabled()
  radcli_dep = dependency('radcli', version: '>= 1.2.5', required: false)
  if not radcli_dep.found()
    radcli_dep = cc.find_library('freeradius-client',
      has_headers: ['freeradius-client.h'], required: false)
    if radcli_dep.found()
      legacy_radius = true
    endif
  endif
  if not radcli_dep.found() and opt_radius.enabled()
    error('RADIUS support requested but neither radcli nor freeradius-client was found')
  endif
endif

# Detect freeradius module directory (for test radiusd.conf generation)
# radius_libdir is the parent of the freeradius/ subdir (e.g. /usr/lib64)
radius_libdir = '/usr/lib'
foreach _pair : [['/usr/lib64/freeradius', '/usr/lib64'],
                 ['/usr/lib/freeradius',   '/usr/lib'],
                 ['/usr/lib/x86_64-linux-gnu/freeradius', '/usr/lib/x86_64-linux-gnu'],
                 ['/usr/lib/aarch64-linux-gnu/freeradius', '/usr/lib/aarch64-linux-gnu']]
  if fs.is_dir(_pair[0])
    radius_libdir = _pair[1]
    break
  endif
endforeach

# GSSAPI + libtasn1
gssapi_dep = dependency('', required: false)
tasn1_dep  = dependency('', required: false)
if not opt_gssapi.disabled()
  gssapi_dep = dependency('krb5-gssapi', required: opt_gssapi)
  if gssapi_dep.found()
    tasn1_dep = dependency('libtasn1', version: '>= 3.4', required: true)
    asn1parser = find_program('asn1Parser', required: false)
  endif
endif

# liboath
oath_dep = dependency('', required: false)
if not opt_liboath.disabled()
  oath_dep = dependency('liboath', required: opt_liboath)
endif

# libnl
libnl_dep = dependency('', required: false)
if not opt_libnl.disabled()
  libnl_dep = dependency('libnl-route-3.0', version: '>= 3.1',
    required: opt_libnl)
endif

# GeoIP: maxmind first, geoip as fallback
maxmind_dep = dependency('', required: false)
geoip_dep   = dependency('', required: false)
if not opt_maxmind.disabled()
  maxmind_dep = dependency('libmaxminddb', version: '>= 1.0.0',
    required: opt_maxmind)
endif
if not maxmind_dep.found() and not opt_geoip.disabled()
  geoip_dep = dependency('geoip', version: '>= 1.6.0', required: opt_geoip)
endif

# readline / libedit
readline_dep = cc.find_library('readline',
  has_headers: ['stdio.h', 'readline/readline.h'], required: false)
have_orig_readline = readline_dep.found()
if not readline_dep.found()
  readline_dep = dependency('libedit', required: false)
endif

# LZ4 (only meaningful when compression is enabled)
lz4_dep = dependency('', required: false)
compression_enabled = get_option('compression').enabled()
if compression_enabled and not opt_lz4.disabled()
  lz4_dep = dependency('liblz4', required: opt_lz4)
endif

# seccomp
seccomp_dep = dependency('', required: false)
if not opt_seccomp.disabled()
  seccomp_dep = cc.find_library('seccomp',
    has_headers: ['seccomp.h'], required: opt_seccomp)
endif

# systemd
systemd_dep = dependency('', required: false)
if not opt_systemd.disabled()
  systemd_dep = cc.find_library('systemd',
    has_headers: ['systemd/sd-daemon.h'], required: opt_systemd)
endif

# OIDC
curl_dep    = dependency('', required: false)
cjose_dep   = dependency('', required: false)
jansson_dep = dependency('', required: false)
oidc_enabled = false
if not opt_oidc.disabled()
  curl_dep    = dependency('libcurl',  required: opt_oidc)
  cjose_dep   = dependency('cjose',    required: opt_oidc)
  jansson_dep = dependency('jansson',  required: opt_oidc)
  oidc_enabled = curl_dep.found() and cjose_dep.found() and jansson_dep.found()
endif

# libwrap (TCP wrappers)
wrap_dep = dependency('', required: false)
if not opt_wrap.disabled()
  wrap_dep = cc.find_library('wrap',
    has_headers: ['tcpd.h'], required: false)
endif

# libcrypt
crypt_dep = cc.find_library('crypt', required: false)

# libutil (utmp)
util_dep = dependency('', required: false)
if not opt_utmp.disabled()
  util_dep = cc.find_library('util',
    has_headers: ['utmpx.h'], required: false)
endif

# libm (for latency stats)
libm_dep = cc.find_library('m', required: false)

# cwrap (for tests only, not required for build)
cwrap_dep     = dependency('uid_wrapper',    required: false)
cwrap_sock    = dependency('socket_wrapper', required: false)
cwrap_pam_dep = dependency('pam_wrapper',    required: false)
cwrap_nss_dep = dependency('nss_wrapper',    required: false)
have_cwrap     = cwrap_dep.found() and cwrap_sock.found()
have_cwrap_pam = have_cwrap and cwrap_pam_dep.found() \
                 and oath_dep.found() and pam_dep.found()
have_cwrap_all = have_cwrap_pam and cwrap_nss_dep.found()

# --------------------------------------------------------------------------
# Feature / version checks
# --------------------------------------------------------------------------

broken_cert = gnutls_dep.version().version_compare('< 3.6.3') and \
              (gnutls_dep.version().version_compare('>= 3.3.99') or \
               gnutls_dep.version().version_compare('< 3.3.25'))
gnutls_new_certs = gnutls_dep.version().version_compare('>= 3.6.0')
old_base64 = nettle_dep.version().version_compare('< 3.0')

latency_enabled = false
if not get_option('latency-stats').disabled()
  latency_enabled = cc.has_header('linux/net_tstamp.h') and \
                    cc.has_type('struct scm_timestamping',
                      prefix: '#include <time.h>\n#include <linux/errqueue.h>')
endif

adaptive_rate = false
adaptive_rate_option = get_option('sock-diag')
if not adaptive_rate_option.disabled()
  have_sockdiag_headers = (
    cc.has_header('linux/netlink.h') and
    cc.has_header('linux/rtnetlink.h') and
    cc.has_header('linux/sock_diag.h') and
    cc.has_header('linux/unix_diag.h')
  )
  if have_sockdiag_headers
    adaptive_rate = true
  elif adaptive_rate_option.enabled()
    error('sock-diag requested but required headers not found')
  endif
endif

proc_fs = fs.exists('/proc/self/exe')

try_sha2_crypt = cc.has_header('gnu/libc-version.h')

have_sighandler_t  = cc.has_type('sighandler_t',
  prefix: '#include <sys/types.h>\n#include <signal.h>')
have_sig_t         = cc.has_type('sig_t',
  prefix: '#include <sys/types.h>\n#include <signal.h>')
have_sighandler2_t = cc.has_type('__sighandler_t',
  prefix: '#include <sys/types.h>\n#include <signal.h>')
have_ucred         = cc.has_type('struct ucred',
  args: ['-D_GNU_SOURCE'],
  prefix: '#include <sys/socket.h>\n#include <sys/un.h>')
have_iphdr_ihl     = cc.has_member('struct iphdr', 'ihl',
  prefix: '#include <netinet/ip.h>')
have_sockaddr_sa_len = cc.has_member('struct sockaddr', 'sa_len',
  prefix: '#include <sys/types.h>\n#include <sys/socket.h>')
sizeof_ulong = cc.sizeof('unsigned long')
words_bigendian = target_machine.endian() == 'big'

have_scm_timestamping = cc.has_type('struct scm_timestamping',
  prefix: '#include <time.h>\n#include <linux/errqueue.h>')

# Function checks
check_funcs = [
  'setproctitle', 'vasprintf', 'clock_gettime', 'isatty',
  'pselect', 'ppoll', 'getpeereid', 'sigaltstack',
  'strlcpy', 'posix_memalign', 'malloc_trim',
  'memset', 'malloc', 'free',
  'makecontext', 'getcontext', 'swapcontext',
  'sigaction', 'longjmp', 'setjmp',
]
func_results = {}
foreach f : check_funcs
  func_results += {f: cc.has_function(f)}
endforeach

# Header checks
check_headers = [
  'net/if_tun.h', 'linux/if_tun.h', 'netinet/in_systm.h', 'crypt.h',
  'linux/net_tstamp.h', 'linux/netlink.h', 'linux/rtnetlink.h',
  'linux/sock_diag.h', 'linux/unix_diag.h',
]
hdr_results = {}
foreach h : check_headers
  hdr_results += {h: cc.has_header(h)}
endforeach

# --------------------------------------------------------------------------
# config.h
# --------------------------------------------------------------------------

cdata = configuration_data()

cdata.set('ANYCONNECT_CLIENT_COMPAT',         get_option('anyconnect-compat').enabled())
cdata.set('CAPTURE_LATENCY_SUPPORT',          latency_enabled)
cdata.set('ENABLE_ADAPTIVE_RATE_LIMIT_SUPPORT', adaptive_rate)
cdata.set('ENABLE_COMPRESSION',               compression_enabled)
cdata.set('GNUTLS_BROKEN_CERTIFICATE_SET_KEY', broken_cert)
cdata.set('HAVE_CWRAP',                       have_cwrap)
cdata.set('HAVE_GEOIP',                       geoip_dep.found())
cdata.set('HAVE_GSSAPI',                      gssapi_dep.found())
cdata.set('HAVE_LIBNL',                       libnl_dep.found())
cdata.set('HAVE_LIBOATH',                     oath_dep.found())
cdata.set('HAVE_LIBTALLOC',                   talloc_dep.found())
cdata.set('HAVE_LIBCRYPT',                    crypt_dep.found())
cdata.set('HAVE_LIBEV',                       true)
cdata.set('HAVE_LIBSECCOMP',                  seccomp_dep.found())
cdata.set('HAVE_LIBSYSTEMD',                  systemd_dep.found())
cdata.set('HAVE_LIBUTIL',                     util_dep.found())
cdata.set('HAVE_LIBWRAP',                     wrap_dep.found())
cdata.set('HAVE_LZ4',                         lz4_dep.found())
cdata.set('HAVE_MAXMIND',                     maxmind_dep.found())
cdata.set('HAVE_ORIG_READLINE',               have_orig_readline)
cdata.set('HAVE_PAM',                         pam_dep.found())
cdata.set('HAVE_RADIUS',                      radcli_dep.found())
cdata.set('LEGACY_RADIUS',                    legacy_radius)
cdata.set('LINUX_NAMESPACES',                 get_option('namespaces').enabled())
cdata.set('NETTLE_OLD_BASE64_API',            old_base64)
cdata.set('PROC_FS_SUPPORTED',                proc_fs)
cdata.set('SUPPORT_OIDC_AUTH',                oidc_enabled)
cdata.set('TRY_SHA2_CRYPT',                   try_sha2_crypt)
cdata.set('USE_SECCOMP_TRAP',                 get_option('seccomp-trap'))
cdata.set('WORKER_MEMORY_LIMIT_TEST',         get_option('worker-memory-limit-test'))

# These three are used in #elif (not #ifdef), so they must be 1 or undef (not empty)
cdata.set('HAVE_SIGHANDLER_T',   have_sighandler_t  ? 1 : false)
cdata.set('HAVE_SIG_T',          have_sig_t         ? 1 : false)
cdata.set('HAVE___SIGHANDLER_T', have_sighandler2_t ? 1 : false)
cdata.set('HAVE_STRUCT_UCRED',                have_ucred)
cdata.set('HAVE_STRUCT_IPHDR_IHL',            have_iphdr_ihl)
cdata.set('HAVE_SOCKADDR_SA_LEN',             have_sockaddr_sa_len)
cdata.set('HAVE_STRUCT_SCM_TIMESTAMPING',     have_scm_timestamping)
cdata.set('SIZEOF_UNSIGNED_LONG',             sizeof_ulong)
cdata.set('WORDS_BIGENDIAN',                  words_bigendian)

foreach f, v : func_results
  cdata.set('HAVE_' + f.to_upper(), v)
endforeach
foreach h, v : hdr_results
  key = 'HAVE_' + h.underscorify().to_upper()
  cdata.set(key, v)
endforeach

# inih tunables
cdata.set('INI_STOP_ON_FIRST_ERROR',  1)
cdata.set('INI_ALLOW_MULTILINE',      1)
cdata.set('INI_MAX_LINE',             2048)
cdata.set_quoted('INI_INLINE_COMMENT_PREFIXES', '#')

# Paths / strings
cdata.set_quoted('OCCTL_PAGER', get_option('pager'))
cdata.set_quoted('OCSERV_FW_SCRIPT',
  get_option('prefix') / get_option('libexecdir') / 'ocserv-fw')

# Package info
cdata.set_quoted('PACKAGE',         'ocserv')
cdata.set_quoted('PACKAGE_NAME',    'OpenConnect VPN Server')
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set_quoted('PACKAGE_STRING',  'OpenConnect VPN Server ' + meson.project_version())
cdata.set_quoted('PACKAGE_TARNAME', 'ocserv')
cdata.set_quoted('PACKAGE_BUGREPORT',
  'https://gitlab.com/openconnect/ocserv/-/issues')
cdata.set_quoted('PACKAGE_URL',     'https://ocserv.openconnect-vpn.net/')
cdata.set_quoted('VERSION',         meson.project_version())

configure_file(output: 'config.h', configuration: cdata)

# --------------------------------------------------------------------------
# Include directories (exported to subdirs)
# --------------------------------------------------------------------------

top_inc    = include_directories('.')          # for config.h
src_inc    = include_directories('src')
common_inc = include_directories('src/common')

# --------------------------------------------------------------------------
# Subdirectories (in migration order)
# --------------------------------------------------------------------------

subdir('src')
subdir('doc')
subdir('tests')

# --------------------------------------------------------------------------
# Dist: pre-generate files that autotools used to ship via EXTRA_DIST
# --------------------------------------------------------------------------

meson.add_dist_script('dist-script.sh')
