if not readline_dep.found()
  # occtl requires readline or libedit
  subdir_done()
endif

occtl_sources = files(
  'occtl.c',
  'pager.c',
  'time.c',
  'cache.c',
  'ip-cache.c',
  'nl.c',
  'print.c',
  'json.c',
  'unix.c',
  'session-cache.c',
)

if maxmind_dep.found()
  occtl_sources += files('maxmind.c')
else
  occtl_sources += files('geoip.c')
endif

occtl_inc = [all_inc, include_directories('.')]

occtl_deps = [
  common_dep, ccan_dep, ipc_dep, protobuf_dep,
  gnutls_dep, nettle_dep,
  talloc_dep, readline_dep,
]

if libnl_dep.found()
  occtl_deps += libnl_dep
endif
if maxmind_dep.found()
  occtl_deps += maxmind_dep
elif geoip_dep.found()
  occtl_deps += geoip_dep
endif

executable('occtl', occtl_sources,
  dependencies: occtl_deps,
  include_directories: occtl_inc,
  install: true,
  install_dir: get_option('bindir'),
)
