cmake_minimum_required(VERSION 3.5)
cmake_policy(SET CMP0048 NEW)

project(packethicn VERSION 0.0.1 DESCRIPTION "hICN protocol plugin" LANGUAGES C)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules"
)

include(BuildMacros)

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(Libhicn REQUIRED)
else()
  if (DISABLE_SHARED_LIBRARIES)
    if (WIN32) 
      set(HICN_LIBRARIES ${LIBHICN_STATIC})
    else ()
      set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    endif ()
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
    )
  else ()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
    )
  endif ()
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
  message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

set(COMPILER_DEFINITIONS -DVERSION=\"${PROJECT_VERSION}\")

set(SOURCE_FILES
  packet-hicn.c
)

list(APPEND PACKETHICN_INCLUDE_DIRS
  ${HICN_INCLUDE_DIRS}
)

list(APPEND LIBRARIES
  ${HICN_LIBRARIES}
  epan
)

build_library(packethicn
  MODULE
  SOURCES ${SOURCE_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT packethicn
  INCLUDE_DIRS ${PACKETHICN_INCLUDE_DIRS}
  INSTALL_FULL_PATH_DIR ${Wireshark_PLUGIN_INSTALL_DIR}/epan
  DEFINITIONS ${COMPILER_DEFINITIONS}
  EMPTY_PREFIX true
)