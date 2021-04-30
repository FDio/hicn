set(LIBFEC_SEARCH_PATH_LIST
  ${LIBFEC_HOME}
  $ENV{DEPENDENCIES}
  $ENV{LIBFEC_HOME}
  /usr/local
  /opt
  /usr
  )

find_path(LIBFEC_INCLUDE_DIR fec/version.h
  HINTS ${LIBFEC_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the LibFec includes" )

find_library(LIBFEC_LIBRARY NAMES fec
  HINTS ${LIBFEC_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the LibFec libraries" )

set(LIBFEC_LIBRARIES ${LIBFEC_LIBRARY})
set(LIBFEC_INCLUDE_DIRS ${LIBFEC_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibFec  DEFAULT_MSG LIBFEC_LIBRARY LIBFEC_INCLUDE_DIR)