# Copyright (c) 2019 Cisco and/or its affiliates.
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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 14)

# -Wno-c99-designator issue
#
# Unsure about version for which this was introduced
# clang version  9.0.8 (no flag), 11.0.5 (ndk22, flag)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  EXECUTE_PROCESS( COMMAND ${CMAKE_CXX_COMPILER} --version OUTPUT_VARIABLE clang_full_version_string )
  string (REGEX REPLACE ".*clang version ([0-9]+\\.[0-9]+).*" "\\1" CLANG_VERSION_STRING ${clang_full_version_string})
  if (CLANG_VERSION_STRING VERSION_GREATER 11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c99-designator")
  endif()
endif()

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_SOURCE_DIR}/cmake/Modules/"
)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE "Release")
endif ()

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

add_subdirectory(includes/hicn/http-proxy)
set(LIBHTTP_PROXY hicnhttpproxy)
set(LIBHTTP_PROXY_STATIC ${LIBHTTP_PROXY}.static)

list(APPEND COMPILER_DEFINITIONS
  -DWITH_POLICY
)

build_library(${LIBHTTP_PROXY}
  STATIC
  SOURCES ${LIB_SOURCE_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  INSTALL_HEADERS ${LIBPROXY_TO_INSTALL_HEADER_FILES}
  INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS} ${LIBHICNCTRL_INCLUDE_DIRS} ${LIBPROXY_INCLUDE_DIRS}
  COMPONENT ${HICN_APPS}
  LINK_FLAGS ${LINK_FLAGS}
  DEFINITIONS ${COMPILER_DEFINITIONS}
)

if (NOT DISABLE_EXECUTABLES)
  build_executable(${HTTP_PROXY}
    SOURCES ${APP_SOURCE_FILES}
    LINK_LIBRARIES ${LIBHTTP_PROXY_STATIC}
    DEPENDS ${LIBHTTP_PROXY_STATIC}
    COMPONENT ${HICN_APPS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    LINK_FLAGS ${LINK_FLAGS}
  )
endif ()
