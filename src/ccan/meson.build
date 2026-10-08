ccan_sources = files(
  'hash/hash.c',
  'htable/htable.c',
  'list/list.c',
  'str/hex/hex.c',
)

if use_local_talloc
  ccan_sources += files('talloc/talloc.c')
endif

libccan = static_library('ccan', ccan_sources,
  include_directories: [top_inc, include_directories('..'), include_directories('.')],
  pic: false,
)

_ccan_inc = [include_directories('..'), include_directories('.')]
if use_local_talloc
  _ccan_inc += include_directories('talloc')
endif

ccan_dep = declare_dependency(
  link_with: libccan,
  include_directories: _ccan_inc,
)
