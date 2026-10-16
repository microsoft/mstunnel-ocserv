libprotobuf_c = static_library('protobuf-c',
  'protobuf-c/protobuf-c.c',
  include_directories: [top_inc, include_directories('.')],
  pic: false,
)

protobuf_dep = declare_dependency(
  link_with: libprotobuf_c,
  include_directories: include_directories('.'),
)
