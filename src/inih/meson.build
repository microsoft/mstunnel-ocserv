libinih = static_library('inih', 'ini.c',
  include_directories: [top_inc, include_directories('.')],
  c_args: [
    '-DINI_STOP_ON_FIRST_ERROR=1',
    '-DINI_ALLOW_MULTILINE=1',
    '-DINI_MAX_LINE=2048',
    '-DINI_INLINE_COMMENT_PREFIXES="#"',
  ],
  pic: false,
)

inih_dep = declare_dependency(
  link_with: libinih,
  include_directories: include_directories('.'),
)
