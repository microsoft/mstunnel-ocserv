libllhttp = static_library('llhttp',
  ['api.c', 'http.c', 'llhttp.c'],
  include_directories: [top_inc, include_directories('.')],
  pic: false,
)

llhttp_dep = declare_dependency(
  link_with: libllhttp,
  include_directories: include_directories('.'),
)
