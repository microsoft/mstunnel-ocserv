# Generate the raddb directory in the build tree.
# radiusd.conf is generated from .in with RADIUS_LIBDIR substituted;
# all other files are copied.  A chmod step removes world/group write
# bits so FreeRADIUS does not refuse to load the configuration.

_raddb_static = ['clients.conf', 'users', 'acct_users',
                 'access_reject', 'accounting_response', 'access_challenge']

_raddb_conf = configure_file(
  input:         'radiusd.conf.in',
  output:        'radiusd.conf',
  configuration: {'RADIUS_LIBDIR': radius_libdir},
)

_raddb_copies = []
foreach _f : _raddb_static
  _raddb_copies += configure_file(input: _f, output: _f, copy: true)
endforeach

# FreeRADIUS refuses to start if any config file is group- or world-writable.
# meson's configure_file honours the process umask, which may be 0000 inside
# containers, producing 0666 files.  Fix permissions after generation.
# build_by_default ensures 'ninja' builds this even without an explicit dep.
raddb_chmod_stamp = custom_target('raddb-chmod',
  input:            [_raddb_conf] + _raddb_copies,
  output:           'raddb-chmod.stamp',
  build_by_default: true,
  command: ['sh', '-c',
    'chmod go-w "$(dirname "$1")" "$@" && touch @OUTPUT@',
    '_dummy',   # $0 (shell script name placeholder)
    '@INPUT@',
  ],
)
