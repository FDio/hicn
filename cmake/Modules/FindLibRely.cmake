set(LIBRELY_SEARCH_PATH_LIST
  ${LIBRELY_HOME}
  $ENV{DEPENDENCIES}
  $ENV{LIBRELY_HOME}
  /usr/local
  /opt
  /usr
  )

find_path(LIBRELY_INCLUDE_DIR rely/version.hpp
  HINTS ${LIBRELY_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the LibRely includes" )

find_library(LIBRELY_LIBRARY NAMES rely
  HINTS ${LIBRELY_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the LibRely libraries" )

set(LIBRELY_LIBRARIES ${LIBRELY_LIBRARY})
set(LIBRELY_INCLUDE_DIRS ${LIBRELY_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibRely  DEFAULT_MSG LIBRELY_LIBRARY LIBRELY_INCLUDE_DIR)