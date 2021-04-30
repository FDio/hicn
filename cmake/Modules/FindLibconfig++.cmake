set(LIBCONFIG_SEARCH_PATH_LIST
  ${LIBCONFIG_HOME}
  $ENV{LIBCONFIG_HOME}
  /usr/local
  /opt
  /usr
)

find_path(LIBCONFIG_INCLUDE_DIR libconfig.h++
  HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the libconfig include"
)

if (WIN32)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    find_library(LIBCONFIG_CPP_LIBRARIES NAMES libconfig++.lib
      HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
      PATH_SUFFIXES lib/x64
      DOC "Find the libconfig libraries"
    )
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    find_library(LIBCONFIG_CPP_LIBRARIES NAMES libconfig++.lib
      HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
      PATH_SUFFIXES lib/x32
      DOC "Find the libconfig libraries"
    )
  endif()
else()
  find_library(LIBCONFIG_CPP_LIBRARY NAMES config++
    HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib
    DOC "Find the libconfig++ libraries"
  )
endif()

set(LIBCONFIG_CPP_LIBRARIES ${LIBCONFIG_CPP_LIBRARY})
set(LIBCONFIG_INCLUDE_DIRS ${LIBCONFIG_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libconfig++ LIBCONFIG_CPP_LIBRARIES LIBCONFIG_INCLUDE_DIRS)


mark_as_advanced(LIBCONFIG_CPP_LIBRARIES LIBCONFIG_INCLUDE_DIRS)
