# Generate PAM service config for the pam-acct tests.
# Requires only pam_wrapper (not socket_wrapper), so it is generated whenever
# cwrap_pam_dep is found, independently of have_cwrap_pam.

pam_acct_conf = configuration_data({
  'ROOTUID':    run_command('id', '-u', check: true).stdout().strip(),
  'ROOTGID':    run_command('id', '-g', check: true).stdout().strip(),
  'PAMWRAPDIR': cwrap_pam_dep.get_variable(pkgconfig: 'modules',
                                            default_value: '/usr/lib/pam_wrapper'),
})

configure_file(
  input:         'ocserv.in',
  output:        'ocserv',
  configuration: pam_acct_conf,
  install:       false,
)
