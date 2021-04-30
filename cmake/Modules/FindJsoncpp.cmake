# Find jsoncpp
#
# Find the jsoncpp includes and library
#
# if you nee to add a custom library search path, do it via via CMAKE_PREFIX_PATH
#
# This module defines
#  JSONCPP_INCLUDE_DIRS, where to find header, etc.
#  JSONCPP_LIBRARIES, the libraries needed to use jsoncpp.
#  JSONCPP_FOUND, If false, do not try to use jsoncpp.
#  JSONCPP_INCLUDE_PREFIX, include prefix for jsoncpp

# only look in default directories
find_path(
        JSONCPP_INCLUDE_DIR
        NAMES jsoncpp/json/json.h json/json.h
        DOC "jsoncpp include dir"
)

find_library(
        JSONCPP_LIBRARY
        NAMES jsoncpp
        DOC "jsoncpp library"
)

set(JSONCPP_INCLUDE_DIRS ${JSONCPP_INCLUDE_DIR})
set(JSONCPP_LIBRARIES ${JSONCPP_LIBRARY})

# find JSONCPP_INCLUDE_PREFIX
find_path(
        JSONCPP_INCLUDE_PREFIX
        NAMES json.h
        PATH_SUFFIXES jsoncpp/json json
)

if (${JSONCPP_INCLUDE_PREFIX} MATCHES "jsoncpp")
    set(JSONCPP_INCLUDE_PREFIX "jsoncpp/json")
else()
    set(JSONCPP_INCLUDE_PREFIX "json")
endif()

# handle the QUIETLY and REQUIRED arguments and set JSONCPP_FOUND to TRUE
# if all listed variables are TRUE, hide their existence from configuration view
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(jsoncpp DEFAULT_MSG
        JSONCPP_INCLUDE_DIR JSONCPP_LIBRARY)
mark_as_advanced (JSONCPP_INCLUDE_DIR JSONCPP_LIBRARY)