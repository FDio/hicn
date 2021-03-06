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

include(GNUInstallDirs)

set(ASIO_STANDALONE 1)

add_subdirectory(core)
add_subdirectory(interfaces)
add_subdirectory(protocols)
add_subdirectory(auth)
add_subdirectory(implementation)
add_subdirectory(utils)
add_subdirectory(http)

include(Packager)
extract_version()
configure_file("config.h.in" "hicn/transport/config.h" @ONLY)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/hicn/transport/config.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hicn/transport
  COMPONENT ${LIBTRANSPORT_COMPONENT}-dev
)

install(
  FILES "transport.config"
  DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/hicn
  COMPONENT ${LIBTRANSPORT_COMPONENT}
)

list(APPEND COMPILER_DEFINITIONS
  "-DASIO_STANDALONE"
)

list(INSERT LIBTRANSPORT_INTERNAL_INCLUDE_DIRS 0
  ${CMAKE_CURRENT_SOURCE_DIR}/
  ${CMAKE_CURRENT_BINARY_DIR}/
)

set(LIBTRANSPORT_INCLUDE_DIRS
  ${LIBTRANSPORT_INCLUDE_DIRS}
  "" CACHE INTERNAL
  "" FORCE
)

if (NOT WIN32)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
else ()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4200 -D_WIN32_WINDOWS=0x0400")
  if (CMAKE_BUILD_TYPE EQUAL "RELEASE")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /NODEFAULTLIB:\"MSVCRTD\"" )
  endif ()
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "Android")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -isystem -lm")
endif()

set (BUILD_TYPES "STATIC")

if (NOT DISABLE_SHARED_LIBRARIES)
  list(APPEND BUILD_TYPES
    "SHARED"
  )
endif()

add_subdirectory(io_modules)

build_library(${LIBTRANSPORT}
  ${BUILD_TYPES}
  SOURCES ${SOURCE_FILES} ${HEADER_FILES}
  INSTALL_HEADERS ${LIBHICNTRANSPORT_TO_INSTALL_HEADER_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  OBJECT_LIBRARIES ${THIRD_PARTY_OBJECT_LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${LIBTRANSPORT_COMPONENT}
  INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS} ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
  HEADER_ROOT_DIR hicn/transport
  DEFINITIONS ${COMPILER_DEFINITIONS}
  VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_REVISION}
)

if (${BUILD_TESTS})
  add_subdirectory(test)
endif()
