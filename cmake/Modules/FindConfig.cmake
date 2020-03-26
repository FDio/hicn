set(LIBCONFIG_SEARCH_PATH_LIST
  ${LIBCONFIG_HOME}
  $ENV{LIBCONFIG_HOME}
  /usr/local
  /opt
  /usr
)

find_path(CONFIG_INCLUDE_DIR libconfig.h
  HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the libconfig include"
)

if (WIN32)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    find_library(CONFIG_LIBRARY NAMES libconfig.lib
      HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
      PATH_SUFFIXES lib/x64
      DOC "Find the libconfig libraries"
    )
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    find_library(CONFIG_LIBRARY NAMES libconfig.lib
      HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
      PATH_SUFFIXES lib/x32
      DOC "Find the libconfig libraries"
    )
  endif()
else()
  find_library(CONFIG_LIBRARY NAMES config
    HINTS ${LIBCONFIG_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib
    DOC "Find the libconfig libraries"
  )
endif()


IF (CONFIG_INCLUDE_DIR AND CONFIG_LIBRARY)
    SET(CONFIG_FOUND TRUE)
ENDIF ( CONFIG_INCLUDE_DIR AND CONFIG_LIBRARY)

IF (CONFIG_FOUND)
    IF (NOT CONFIG_FIND_QUIETLY)
	MESSAGE(STATUS "Found Config: ${CONFIG_LIBRARY}")
    ENDIF (NOT  CONFIG_FIND_QUIETLY)
ELSE(CONFIG_FOUND)
    IF (Config_FIND_REQUIRED)
	IF(NOT CONFIG_INCLUDE_DIR)
	    MESSAGE(FATAL_ERROR "Could not find LibConfig header file!")
	ENDIF(NOT CONFIG_INCLUDE_DIR)

	IF(NOT CONFIG_LIBRARY)
	    MESSAGE(FATAL_ERROR "Could not find LibConfig library file!")
	ENDIF(NOT CONFIG_LIBRARY)
    ENDIF (Config_FIND_REQUIRED)
ENDIF (CONFIG_FOUND)