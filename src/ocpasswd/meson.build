executable('ocpasswd', 'ocpasswd.c',
  dependencies: [gnutls_dep, nettle_dep, crypt_dep],
  include_directories: [all_inc, include_directories('.')],
  install: true,
  install_dir: get_option('bindir'),
)
