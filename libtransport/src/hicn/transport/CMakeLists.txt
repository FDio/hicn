# Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

include(GNUInstallDirs)

set(ASIO_STANDALONE 1)

add_subdirectory(core)
add_subdirectory(errors)
add_subdirectory(http)
add_subdirectory(interfaces)
add_subdirectory(portability)
add_subdirectory(protocols)
add_subdirectory(utils)

include(Packager)
extract_version()
configure_file("config.h.in" "config.h" @ONLY)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hicn/transport
  COMPONENT lib${LIBTRANSPORT}-dev
)

set (COMPILER_DEFINITIONS "-DTRANSPORT_LOG_DEF_LEVEL=TRANSPORT_LOG_${TRANSPORT_LOG_LEVEL}")

list(INSERT LIBTRANSPORT_INTERNAL_INCLUDE_DIRS 0
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_BINARY_DIR}/../..
)

set(LIBTRANSPORT_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/../../
  ${CMAKE_CURRENT_BINARY_DIR}/../../
  "" CACHE INTERNAL
  "" FORCE
)

if (NOT WIN32)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
else ()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4200")
  if (CMAKE_BUILD_TYPE EQUAL "RELEASE")
    set(CMAKE_SHARED_LINKER_FLAGS "/NODEFAULTLIB:\"MSVCRTD\"" )
  endif ()
endif ()
if (${CMAKE_SYSTEM_NAME} STREQUAL "Android")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -isystem -lm")
endif()

if (DISABLE_SHARED_LIBRARIES)
  build_library(${LIBTRANSPORT}
    STATIC
    SOURCES ${SOURCE_FILES} ${HEADER_FILES}
    INSTALL_HEADERS ${HEADER_FILES}
    LINK_LIBRARIES ${LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT lib${LIBTRANSPORT}
    INCLUDE_DIRS ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
    INSTALL_ROOT_DIR hicn/transport
    DEFINITIONS ${COMPILER_DEFINITIONS}
  )
else ()
  build_library(${LIBTRANSPORT}
    STATIC SHARED
    SOURCES ${SOURCE_FILES} ${HEADER_FILES}
    INSTALL_HEADERS ${HEADER_FILES}
    LINK_LIBRARIES ${LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT lib${LIBTRANSPORT}
    INCLUDE_DIRS ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
    INSTALL_ROOT_DIR hicn/transport
    DEFINITIONS ${COMPILER_DEFINITIONS}
  )
endif ()

if (${COMPILE_TESTS})
  add_subdirectory(core/test)
  add_subdirectory(transport/test)
endif()
