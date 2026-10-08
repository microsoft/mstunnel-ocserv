ronn = find_program('ronn', required: false)

foreach page : ['ocserv.8', 'occtl.8', 'ocpasswd.8']
  if ronn.found()
    custom_target(page,
      input:       page + '.md',
      output:      page,
      command:     [ronn, '--roff', '@INPUT@', '-o', '@OUTDIR@'],
      install:     true,
      install_dir: get_option('mandir') / 'man8',
    )
  elif fs.exists(page)
    install_data(page,
      install_dir: get_option('mandir') / 'man8',
    )
  endif
endforeach
