# Copyright (c) 2021-2022 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##############################################################
# Compiler options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)

# -Wno-c99-designator issue
#
# Unsure about version for which this was introduced
# clang version  9.0.8 (no flag), 11.0.5 (ndk22, flag)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  EXECUTE_PROCESS( COMMAND ${CMAKE_CXX_COMPILER} --version OUTPUT_VARIABLE clang_full_version_string )
  string (REGEX REPLACE ".*clang version ([0-9]+\\.[0-9]+).*" "\\1" CLANG_VERSION_STRING ${clang_full_version_string})
  if (CLANG_VERSION_STRING VERSION_GREATER_EQUAL 11)
    list(APPEND COMPILER_OPTIONS
      "-Wno-c99-designator"
    )
  endif()
endif()


##############################################################
# Includes subdirectory
##############################################################
add_subdirectory(includes/hicn/http-proxy)


##############################################################
# Source files
##############################################################
set(LIB_SOURCE_FILES
  src/http_session.cc
  src/http_proxy.cc
  src/http_1x_message_fast_parser.cc
  src/icn_receiver.cc
  src/forwarder_interface.cc
)

set(APP_SOURCE_FILES
  main.cc
)

##############################################################
# Libraries to link
##############################################################
list(APPEND HTTP_PROXY_LIBRARIES
  PUBLIC ${LIBTRANSPORT_LIBRARIES}
  PUBLIC ${LIBHICNCTRL_LIBRARIES}
  PUBLIC ${LIBHICN_LIBRARIES}
  PRIVATE ${CMAKE_THREAD_LIBS_INIT}
)


##############################################################
# Build http proxy library
##############################################################
build_library(${LIBHTTP_PROXY}
  STATIC
  SOURCES ${LIB_SOURCE_FILES}
  LINK_LIBRARIES ${HTTP_PROXY_LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  INSTALL_HEADERS ${LIBPROXY_TO_INSTALL_HEADER_FILES}
  INCLUDE_DIRS
    PUBLIC
      $<BUILD_INTERFACE:${LIBPROXY_INCLUDE_DIRS}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  COMPONENT ${HICN_APPS}
  LINK_FLAGS ${LINK_FLAGS}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)


##############################################################
# Build http proxy executable
##############################################################
if (NOT DISABLE_EXECUTABLES)
  build_executable(${HTTP_PROXY}
    SOURCES ${APP_SOURCE_FILES}
    LINK_LIBRARIES ${LIBHTTP_PROXY_STATIC}
    DEPENDS ${LIBHTTP_PROXY_STATIC}
    COMPONENT ${HICN_APPS}
    LINK_FLAGS ${LINK_FLAGS}
  )
endif ()
