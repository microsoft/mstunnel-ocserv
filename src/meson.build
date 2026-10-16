# --------------------------------------------------------------------------
# Bundled static libraries
# --------------------------------------------------------------------------

subdir('ccan')
subdir('inih')
subdir('pcl')

if use_local_llhttp
  subdir('llhttp')
# else: llhttp_dep already set by cc.find_library() in top-level meson.build
endif

if use_local_protobuf
  subdir('protobuf')
else
  # protobuf_dep already set in top-level meson.build
endif

# --------------------------------------------------------------------------
# Include directories
# --------------------------------------------------------------------------

src_build_inc = include_directories('.')   # for generated headers (pb-c, http-heads)

all_inc = [top_inc, src_inc, src_build_inc, common_inc]

if use_local_talloc
  all_inc += include_directories('ccan/talloc')
endif
if use_local_protobuf
  all_inc += include_directories('protobuf')
endif
if use_local_llhttp
  all_inc += include_directories('llhttp')
endif

# --------------------------------------------------------------------------
# Generated sources
# --------------------------------------------------------------------------

# version.inc
version_inc = configure_file(
  input:         'version.inc.in',
  output:        'version.inc',
  configuration: {'VERSION': meson.project_version()},
)

# Protocol buffers
if protoc.found()
  ipc_proto = custom_target('ipc-proto',
    input:   'ipc.proto',
    output:  ['ipc.pb-c.c', 'ipc.pb-c.h'],
    command: [protoc, '--c_out=@OUTDIR@',
              '--proto_path=@CURRENT_SOURCE_DIR@', '@INPUT@'],
  )
  ctl_proto = custom_target('ctl-proto',
    input:   'ctl.proto',
    output:  ['ctl.pb-c.c', 'ctl.pb-c.h'],
    depends: ipc_proto,
    command: [protoc, '--c_out=@OUTDIR@',
              '--proto_path=@CURRENT_SOURCE_DIR@', '@INPUT@'],
  )
  cfg_proto = custom_target('cfg-proto',
    input:   'cfg.proto',
    output:  ['cfg.pb-c.c', 'cfg.pb-c.h'],
    depends: ipc_proto,
    command: [protoc, '--c_out=@OUTDIR@',
              '--proto_path=@CURRENT_SOURCE_DIR@', '@INPUT@'],
  )
elif fs.exists('ipc.pb-c.c') and fs.exists('ctl.pb-c.c') and fs.exists('cfg.pb-c.c')
  ipc_proto = files('ipc.pb-c.c', 'ipc.pb-c.h')
  ctl_proto = files('ctl.pb-c.c', 'ctl.pb-c.h')
  cfg_proto = files('cfg.pb-c.c', 'cfg.pb-c.h')
else
  error('protoc-c not found and no pre-generated pb-c files present')
endif

# gperf HTTP header table
if gperf.found()
  http_heads_c = custom_target('http-heads',
    input:   'http-heads.gperf',
    output:  'http-heads.c',
    command: [gperf, '--global-table', '-t', '@INPUT@', '--output-file', '@OUTPUT@'],
  )
elif fs.exists('http-heads.c')
  http_heads_c = files('http-heads.c')
else
  error('gperf not found and no pre-generated http-heads.c present')
endif

# ASN.1 (GSSAPI / KKDCP)
kkdcp_asn1 = []
if gssapi_dep.found()
  if asn1parser.found()
    kkdcp_asn1 = custom_target('kkdcp-asn1',
      input:   'kkdcp.asn',
      output:  'kkdcp_asn1_tab.c',
      command: [asn1parser, '-o', '@OUTPUT@', '@INPUT@'],
    )
  elif fs.exists('kkdcp_asn1_tab.c')
    kkdcp_asn1 = files('kkdcp_asn1_tab.c')
  else
    error('GSSAPI enabled but asn1Parser not found and no pre-generated kkdcp_asn1_tab.c present')
  endif
endif

# --------------------------------------------------------------------------
# libipc (protobuf stubs shared by ocserv and occtl)
# --------------------------------------------------------------------------

libipc = static_library('ipc', [ipc_proto, ctl_proto, cfg_proto],
  include_directories: all_inc,
  dependencies: protobuf_dep,
  pic: false,
)

ipc_dep = declare_dependency(
  link_with: libipc,
  include_directories: src_build_inc,
  sources: [ipc_proto, ctl_proto, cfg_proto],
)

# --------------------------------------------------------------------------
# libcommon (shared by ocserv, occtl, tests)
# --------------------------------------------------------------------------

libcommon = static_library('common',
  files(
    'common/common.c',
    'common/system.c',
    'common/base64-helper.c',
    'log.c',
  ),
  include_directories: all_inc,
  dependencies: [gnutls_dep, nettle_dep, protobuf_dep, ipc_dep],
  pic: false,
)

common_dep = declare_dependency(
  link_with: libcommon,
  include_directories: [src_inc, common_inc, top_inc],
)

# --------------------------------------------------------------------------
# CORE_SOURCES shared by ocserv and ocserv-worker
# --------------------------------------------------------------------------

core_sources = files(
  'common/hmac.c',
  'common/snapshot.c',
  'config.c',
  'config-kkdcp.c',
  'config-ports.c',
  'gnulib/cloexec.c',
  'setproctitle.c',
  'str.c',
  'subconfig.c',
  'sup-config/file.c',
  'sup-config/radius.c',
  'tlslib.c',
  'valid-hostname.c',
  'vasprintf.c',
  'worker-log.c',
  'ip-util.c',
)

if compression_enabled
  core_sources += files('lzs.c')
endif

if gssapi_dep.found()
  core_sources += [kkdcp_asn1]
endif

# Authentication sources
auth_sources = files(
  'auth/common.c',
  'auth/gssapi.c',
  'auth/pam.c',
  'auth/plain.c',
  'auth/radius.c',
  'auth-unix.c',
)

if oidc_enabled
  auth_sources += files('auth/openidconnect.c')
endif

# Accounting sources
acct_sources = files(
  'acct/radius.c',
  'acct/pam.c',
)

# --------------------------------------------------------------------------
# Dependency list shared by ocserv and ocserv-worker
# --------------------------------------------------------------------------

core_deps = [
  common_dep, ccan_dep, inih_dep, ipc_dep, protobuf_dep,
  llhttp_dep, pcl_dep,
  gnutls_dep, nettle_dep, libev_dep,
  crypt_dep, util_dep, wrap_dep,
  lz4_dep, seccomp_dep, systemd_dep,
  talloc_dep, oath_dep,
]

if pam_dep.found()
  core_deps += pam_dep
endif
if radcli_dep.found()
  core_deps += radcli_dep
endif
if gssapi_dep.found()
  core_deps += [gssapi_dep, tasn1_dep]
endif
if oidc_enabled
  core_deps += [curl_dep, cjose_dep, jansson_dep]
endif

# --------------------------------------------------------------------------
# ocserv
# --------------------------------------------------------------------------

ocserv_sources = core_sources + auth_sources + acct_sources + files(
  'main.c',
  'main-auth.c',
  'main-ban.c',
  'main-ctl-unix.c',
  'main-proc.c',
  'main-sec-mod-cmd.c',
  'main-user.c',
  'main-worker-cmd.c',
  'proc-search.c',
  'route-add.c',
  'sec-mod.c',
  'sec-mod-auth.c',
  'sec-mod-cookies.c',
  'sec-mod-db.c',
  'sec-mod-resume.c',
  'sec-mod-sup-config.c',
  'common/sockdiag.c',
  'namespace.c',
  'main-log.c',
  'icmp-ping.c',
  'ip-lease.c',
  'tun.c',
  'main-limits.c',
)

executable('ocserv', ocserv_sources,
  dependencies: core_deps,
  include_directories: all_inc,
  install: true,
  install_dir: get_option('sbindir'),
)

# --------------------------------------------------------------------------
# ocserv-worker
# --------------------------------------------------------------------------

worker_sources = core_sources + [http_heads_c] + files(
  'html.c',
  'worker.c',
  'worker-auth.c',
  'worker-bandwidth.c',
  'worker-http.c',
  'worker-http-handlers.c',
  'worker-kkdcp.c',
  'worker-misc.c',
  'worker-privs.c',
  'worker-proxyproto.c',
  'worker-resume.c',
  'worker-vpn.c',
  'worker-svc.c',
  'worker-tun.c',
  'isolate.c',
)

worker_deps = core_deps
if latency_enabled
  worker_sources += files('worker-latency.c')
  worker_deps += libm_dep
endif

executable('ocserv-worker', worker_sources,
  c_args: ['-DOCSERV_WORKER_PROCESS'],
  dependencies: worker_deps,
  include_directories: all_inc,
  install: true,
  install_dir: get_option('sbindir'),
)

# --------------------------------------------------------------------------
# ocserv-fw script
# --------------------------------------------------------------------------

if fw_script_type == 'nftables'
  _fw_src = 'ocserv-fw-nftables'
else
  _fw_src = 'ocserv-fw-iptables'
endif
install_data(_fw_src,
  rename:       'ocserv-fw',
  install_dir:  get_option('libexecdir'),
  install_mode: 'rwxr-xr-x',
)

# --------------------------------------------------------------------------
# Subdirectories for occtl and ocpasswd
# --------------------------------------------------------------------------

subdir('occtl')
subdir('ocpasswd')
