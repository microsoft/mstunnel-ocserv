test_inc = [top_inc, src_inc, src_build_inc, common_inc]

test_base_deps = [common_dep, ccan_dep, nettle_dep, talloc_dep, llhttp_dep, protobuf_dep, ipc_dep]

# Tests run with cwd = build tests/ dir; source paths in configs use @SRCDIR@
test_workdir = meson.current_build_dir()

test_env = environment()
test_env.set('srcdir',       meson.current_source_dir())
test_env.set('top_builddir', meson.build_root())
test_env.set('builddir',     meson.current_build_dir())
test_env.set('LSAN_OPTIONS', 'suppressions=' + meson.current_source_dir() / 'asan.supp')
test_env.set('SERV',         meson.build_root() / 'src' / 'ocserv')
test_env.set('OCCTL',        meson.build_root() / 'src' / 'occtl' / 'occtl')
test_env.set('OCPASSWD',     meson.build_root() / 'src' / 'ocpasswd' / 'ocpasswd')

# --------------------------------------------------------------------------
# Generate raddb directory in the build tree
# radiusd.conf is generated from radiusd.conf.in with RADIUS_LIBDIR substituted.
# All other static files are copied so radiusd -d <raddb_build_dir> works.
# The subdir() call below outputs files into build/tests/data/raddb/.
# --------------------------------------------------------------------------

raddb_build_dir = meson.current_build_dir() / 'data' / 'raddb'
test_env.set('RADDB_DIR', raddb_build_dir)
subdir('data/raddb')

radiusclient_build_dir = meson.current_build_dir() / 'data' / 'radiusclient'
test_env.set('RADIUSCLIENT_DIR', radiusclient_build_dir)
subdir('data/radiusclient')

# --------------------------------------------------------------------------
# C unit tests
# --------------------------------------------------------------------------

unit_tests = {
  'str-test':       {'src': ['str-test.c'],      'args': [], 'timeout': 30},
  'str-test2':      {'src': ['str-test2.c'],     'args': [], 'timeout': 30},
  'bearer-auth':     {'src': ['bearer-auth.c'],   'args': [], 'timeout': 30},
  'kkdcp-parsing':  {'src': ['kkdcp-parsing.c'], 'args': [], 'timeout': 30},
  'json-escape':    {'src': ['json-escape.c'],   'args': [], 'timeout': 30},
  'ban-ips':        {'src': ['ban-ips.c'],        'args': ['-DUNDER_TEST'], 'timeout': 120},
  'port-parsing':   {'src': ['port-parsing.c'],  'args': ['-DUNDER_TEST'], 'timeout': 30},
  'human_addr':     {'src': ['human_addr.c'],    'args': ['-DUNDER_TEST'], 'timeout': 30},
  'valid-hostname': {'src': ['valid-hostname.c'], 'args': [], 'timeout': 30},
  'url-escape':     {'src': ['url-escape.c'],    'args': ['-DUNDER_TEST'], 'timeout': 30},
  'html-escape':    {'src': ['html-escape.c'],   'args': ['-DUNDER_TEST'], 'timeout': 30},
  'ipv4-prefix':    {'src': ['ipv4-prefix.c'],   'args': ['-DUNDER_TEST'], 'timeout': 30},
  'ipv6-prefix':    {'src': ['ipv6-prefix.c'],   'args': ['-DUNDER_TEST'], 'timeout': 30},
  'proxyproto-v1':  {'src': ['proxyproto-v1.c'], 'args': [], 'timeout': 30},
  'proxyproto-v2':  {'src': ['proxyproto-v2.c'], 'args': [], 'timeout': 30},
}

foreach name, cfg : unit_tests
  exe = executable(name, cfg['src'],
    c_args: cfg['args'],
    dependencies: test_base_deps,
    include_directories: test_inc,
  )
  test(name, exe, env: test_env, workdir: test_workdir, timeout: cfg['timeout'])
endforeach

# cstp-recv needs gnutls
cstp_recv_exe = executable('cstp-recv', 'cstp-recv.c',
  dependencies: test_base_deps + [gnutls_dep],
  include_directories: test_inc,
)
test('cstp-recv', cstp_recv_exe, env: test_env, workdir: test_workdir)

# config-inherit: exercises vhost config inheritance (#705).
# Textually includes config.c and its dependencies so that the static
# parse_cfg_file() is accessible from the test.  Requires gnutls (for
# gnutls_idna_map / gnutls_check_version called from config.c) and inih
# (for ini_parse).
config_inherit_exe = executable('config-inherit', 'config-inherit.c',
  c_args: ['-DOCSERV_WORKER_PROCESS'],
  dependencies: test_base_deps + [gnutls_dep, inih_dep, ipc_dep, pcl_dep],
  include_directories: test_inc,
)
test('config-inherit', config_inherit_exe,
  env: test_env, workdir: test_workdir, timeout: 30)

# pam-guard-page: verifies that the PROT_NONE guard page beneath the PCL
# coroutine stack converts a stack overflow into a crash (#619, #657).
# Linux only; returns 77 (skip) on other platforms.
if pam_dep.found()
  pam_guard_page_exe = executable('pam-guard-page', 'pam-guard-page.c',
    dependencies: test_base_deps + [pcl_dep],
    include_directories: test_inc,
  )
  test('pam-guard-page', pam_guard_page_exe,
    env: test_env, workdir: test_workdir, timeout: 30)
endif

# gen_oidc_test_data (only when OIDC enabled)
if oidc_enabled
  gen_oidc_exe = executable('gen_oidc_test_data', 'generate_oidc_test_data.c',
    dependencies: test_base_deps + [cjose_dep, jansson_dep],
    include_directories: test_inc,
  )
endif

# --------------------------------------------------------------------------
# Shell script tests – always run
# --------------------------------------------------------------------------

always_scripts = [
  'ocpasswd-test',
  'test-owasp-headers',
  'test-replay',
  'test-fw-normalize-route',
  'test-http-limits',
  'test-http-smuggling',
  'test-cookie-sid-overflow',
]

foreach s : always_scripts
  test(s, find_program(s),
    env:     test_env,
    timeout: 120,
    workdir: test_workdir,
  )
endforeach

# --------------------------------------------------------------------------
# Shell script tests – require cwrap
# --------------------------------------------------------------------------

if have_cwrap
  # syslog-shim: LD_PRELOAD library used by test-syslog-facility to intercept
  # openlog(3) and record the facility argument without a real syslog daemon.
  syslog_shim = shared_library('syslog-shim', 'syslog-shim.c',
    dependencies: [meson.get_compiler('c').find_library('dl', required: false)],
    install: false,
  )
  test_env.set('SYSLOG_SHIM', syslog_shim.full_path())

  cwrap_scripts = [
    'test-pass', 'test-pass-cert', 'test-pass-cert-rfc822name',
    'test-cert', 'test-group-pass', 'test-pass-group-cert',
    'test-pass-group-cert-no-pass', 'test-sighup',
    'test-enc-key', 'test-sighup-key-change',
    'test-san-cert', 'test-pass-opt-cert',
    'test-cert-opt-pass',
    'haproxy-auth', 'test-maintenance', 'resumption',
    'test-group-name', 'flowcontrol', 'banner', 'invalid-configs',
    'haproxy-proxyproto', 'haproxy-proxyproto-v1',
    'drain-server', 'drain-server-fail',
    'test-ignore-querystring-of-post',
    'test-group-cert', 'test-fork', 'test-pass-svc', 'test-cert-svc',
    'test-secmod-kill', 'test-syslog-facility',
  ]

  if have_cwrap_all
    cwrap_scripts += ['test-vhost']
  endif

  foreach s : cwrap_scripts
    test(s, find_program(s),
      env:     test_env,
      timeout: 180,
      workdir: test_workdir,
    )
  endforeach

  # gssapi tests are expected to fail on Ubuntu22 (openssl doesn't support md4)
  # https://bugs.launchpad.net/ubuntu/+source/gss-ntlmssp/+bug/1995915
  foreach s : ['test-gssapi', 'test-gssapi-opt-pass', 'test-gssapi-opt-cert']
    test(s, find_program(s),
      env:     test_env,
      timeout: 180,
      workdir: test_workdir,
      suite:   'gssapi',
    )
  endforeach

  if have_cwrap_pam
    # Detection module for the pam_auth_deinit coroutine-safety test (#657).
    pam_abort_mod = shared_module('pam_abort_test', 'pam-abort-mod.c',
      dependencies: [pam_dep],
      name_prefix:  '',
      install:      false,
    )

    # Generate PAM test data files from templates into builddir/data/pam/
    # common.sh expects: ${builddir}/data/pam/{nss-passwd,nss-group,ocserv}
    pam_conf = configuration_data({
      'ROOTUID':       run_command('id', '-u', check: true).stdout().strip(),
      'ROOTGID':       run_command('id', '-g', check: true).stdout().strip(),
      'PAMWRAPDIR':    cwrap_pam_dep.get_variable(pkgconfig: 'modules',
                                                  default_value: '/usr/lib/pam_wrapper'),
      'PAM_ABORT_MOD': pam_abort_mod.full_path(),
    })
    subdir('data/pam')

    foreach s : ['test-pam', 'test-pam-noauth']
      test(s, find_program(s),
        env:     test_env,
        timeout: 180,
        workdir: test_workdir,
      )
    endforeach

    test('test-pam-abort', find_program('test-pam-abort'),
      env:     test_env,
      timeout: 90,
      workdir: test_workdir,
    )

    if get_option('kerberos-tests')
      test('kerberos', find_program('kerberos'),
        env:     test_env,
        timeout: 300,
        workdir: test_workdir,
      )
    endif
  endif

  if oath_dep.found()
    foreach s : ['test-otp-cert', 'test-otp']
      test(s, find_program(s),
        env:     test_env,
        timeout: 180,
        workdir: test_workdir,
      )
    endforeach
  endif
endif

# new-cert tests (Ed25519, RSA-PSS) require GnuTLS >= 3.6.0
if gnutls_new_certs
  foreach s : ['server-cert-ed25519', 'server-cert-rsa-pss']
    test(s, find_program(s),
      env:     test_env,
      timeout: 180,
      workdir: test_workdir,
    )
  endforeach
endif

# OIDC test
if oidc_enabled
  # gen_oidc_test_data must run before test-oidc to generate data/oidc.json and
  # the token files consumed by the test.  Use priority so meson schedules it
  # first (higher priority runs first).
  test('gen_oidc_test_data', gen_oidc_exe,
    env:          test_env,
    timeout:      30,
    workdir:      test_workdir,
    priority:     1,
  )
  test('test-oidc', find_program('test-oidc'),
    env:          test_env,
    timeout:      180,
    workdir:      test_workdir,
    priority:     0,
  )
endif

# tun tests (require /dev/net/tun)
if get_option('tun-tests')
  foreach s : ['no-route-default', 'no-route-group']
    test(s, find_program(s),
      env:     test_env,
      timeout: 180,
      workdir: test_workdir,
    )
  endforeach
endif

if have_cwrap_pam
  subdir('data/pam-acct')
endif

# --------------------------------------------------------------------------
# Shell script tests – require root / namespaces
# --------------------------------------------------------------------------

if get_option('root-tests')
  foreach s : ['test-fw-script', 'fw-ocserv', 'fw-ocserv-ports-routes']
    test(s, find_program(s),
      env:     test_env,
      timeout: 300,
      workdir: test_workdir,
      suite:   'fw',
    )
  endforeach

  root_scripts = [
    'haproxy-connect', 'test-iroute', 'test-multi-cookie',
    'test-pass-script', 'idle-timeout', 'idle-timeout-icmpv6', 'test-year-2038',
    'test-cookie-timeout', 'test-cookie-timeout-2',
    'test-explicit-ip', 'test-cookie-invalidation',
    'test-user-config', 'test-append-routes', 'test-ban',
    'multiple-routes', 'json', 'test-udp-listen-host',
    'test-max-same-1', 'test-vhost-udp-port-inheritance',
    'apple-ios', 'ipv6-iface', 'test-no-udp',
    'test-cstp-send-hang', 'test-mtu-connect',
    'disconnect-user', 'disconnect-user2', 'terminate-commands',
    'ping-leases', 'test-ban-local', 'test-client-bypass-protocol',
    'ipv6-small-net', 'test-camouflage', 'test-camouflage-norealm',
    'vhost-traffic', 'defvhost-traffic', 'session-timeout',
    'test-occtl', 'test-occtl-commands', 'no-ipv6-ocv3',
    # cipher / traffic tests
    'traffic', 'bandwidth', 'lz4-compression', 'lzs-compression',
    'aes256-cipher', 'aes128-cipher',
    'oc-aes256-gcm-cipher', 'oc-aes128-gcm-cipher',
    'ac-aes128-gcm-cipher', 'ac-aes256-gcm-cipher',
    'no-dtls-cipher', 'psk-negotiate', 'psk-negotiate-match',
    'test-config-per-group', 'test-config-per-group-url-pass',
    'test-config-per-group-url-cert', 'test-multiple-client-ip',
  ]

  foreach s : root_scripts
    test(s, find_program(s),
      env:     test_env,
      timeout: 300,
      workdir: test_workdir,
    )
  endforeach

  # PAM accounting test requires PAM support compiled in and pam_wrapper
  if have_cwrap_pam
    test('test-pass-pam-acct', find_program('test-pass-pam-acct'),
      env:     test_env,
      timeout: 300,
      workdir: test_workdir,
    )
  endif

  if get_option('namespaces').enabled()
    test('test-namespace-listen', find_program('test-namespace-listen'),
      env:     test_env,
      timeout: 300,
      workdir: test_workdir,
    )
  endif

  if radcli_dep.found()
    foreach s : ['radius', 'radius-group', 'radius-multi-group',
                 'radius-multi-group-comma', 'radius-otp', 'radius-config',
                 'radius-ipv6-prefix']
      test(s, find_program(s),
        env:     test_env,
        timeout: 300,
        workdir: test_workdir,
        depends: [raddb_chmod_stamp],
      )
    endforeach
  endif

  test('test-script-multi-user', find_program('test-script-multi-user'),
    env:     test_env,
    timeout: 300,
    workdir: test_workdir,
  )
endif
