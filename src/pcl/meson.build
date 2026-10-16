libpcl = static_library('pcl',
  ['pcl.c', 'pcl_version.c', 'pcl_private.c'],
  c_args: ['-DHAVE_CONFIG_H'],
  include_directories: [top_inc, include_directories('.')],
  pic: false,
)

pcl_dep = declare_dependency(
  link_with: libpcl,
  include_directories: include_directories('.'),
)
