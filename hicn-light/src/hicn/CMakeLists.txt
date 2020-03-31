# Define a few configuration variables that we want accessible in the software

include(BuildMacros)
configure_file(config.h.in hicn-light/config.h @ONLY)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" AND ENABLE_PUNTING)
  list(APPEND COMPILER_DEFINITIONS
    "-DPUNTING"
  )
endif()

list(APPEND COMPILER_DEFINITIONS
#  "-DWITH_GRO"
#  "-DWITH_GSO"
#  "-DWITH_ZEROCOPY"
  "-DWITH_MAPME"
  "-DWITH_POLICY"
  "-DWITH_PREFIX_STATS"
#  "-DNDEBUG=1" # disable assertions
)

if (NOT DISABLE_EXECUTABLES)
  add_subdirectory(command_line)
endif()

add_subdirectory(base)
add_subdirectory(config)
add_subdirectory(content_store)
add_subdirectory(core)
add_subdirectory(io)
add_subdirectory(messenger)
add_subdirectory(platforms)
add_subdirectory(processor)
add_subdirectory(socket)
add_subdirectory(strategies)
add_subdirectory(utils)

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_BINARY_DIR}/hicn-light/config.h
)

list(INSERT HICN_LIGHT_INCLUDE_DIRS 0
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_BINARY_DIR}/..
)

list(APPEND TO_INSTALL_HEADER_FILES
  ${CMAKE_CURRENT_BINARY_DIR}/hicn-light/config.h
)

if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Android")
  set(LIB_BUILD_TYPE "NO_DEV")
else()
  set(LIB_BUILD_TYPE "")
endif()

build_library(${LIBHICN_LIGHT}
  STATIC ${LIB_BUILD_TYPE}
  SOURCES ${SOURCE_FILES}
  INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${HICN_LIGHT}
  INCLUDE_DIRS ${HICN_LIGHT_INCLUDE_DIRS}
  INSTALL_ROOT_DIR hicn
  DEFINITIONS ${COMPILER_DEFINITIONS}
)

