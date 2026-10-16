# Generate PAM test data files substituting @ROOTUID@, @ROOTGID@, @PAMWRAPDIR@
# pam_conf is defined by the parent (tests/meson.build) before calling subdir()

configure_file(
  input:         'nss-passwd.in',
  output:        'nss-passwd',
  configuration: pam_conf,
  install:       false,
)

configure_file(
  input:         'nss-group.in',
  output:        'nss-group',
  configuration: pam_conf,
  install:       false,
)

configure_file(
  input:         'ocserv.in',
  output:        'ocserv',
  configuration: pam_conf,
  install:       false,
)

configure_file(
  input:         'ocserv-vhost1.in',
  output:        'ocserv-vhost1',
  configuration: pam_conf,
  install:       false,
)

configure_file(
  input:         'ocserv-vhost2.in',
  output:        'ocserv-vhost2',
  configuration: pam_conf,
  install:       false,
)

configure_file(
  input:         'ocserv-abort.in',
  output:        'ocserv-abort',
  configuration: pam_conf,
  install:       false,
)
