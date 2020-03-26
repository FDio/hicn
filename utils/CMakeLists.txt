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
set(CMAKE_CXX_STANDARD 14)

project(utils)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE "Release")
endif ()

include(BuildMacros)
include(WindowsMacros)

set(HICN_UTILS hicn-utils CACHE INTERNAL "" FORCE)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(Libtransport REQUIRED)
else()
  if (DISABLE_SHARED_LIBRARIES)
    set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_STATIC})
    set(DEPENDENCIES ${LIBTRANSPORT_STATIC})
  else ()
    set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_SHARED})
    set(DEPENDENCIES ${LIBTRANSPORT_SHARED})
  endif ()

endif()

set(SUFFIX "")
if (${LIBTRANSPORT_LIBRARIES} MATCHES ".*-memif.*")
  set(SUFFIX "-memif")
  set(LINK_FLAGS "-Wl,-unresolved-symbols=ignore-in-shared-libs")
endif()

set(HICN_UTILS "${HICN_UTILS}${SUFFIX}")

set (COMPILER_DEFINITIONS "")

if (WIN32)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4200 /wd4996")
endif ()

include(Packaging)

if (NOT DISABLE_EXECUTABLES)
  build_executable(hiperf
    SOURCES src/hiperf.cc
    LINK_LIBRARIES ${LIBTRANSPORT_LIBRARIES} ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
    INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${HICN_UTILS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    LINK_FLAGS ${LINK_FLAGS}
  )

  build_executable(hicn-ping-server
    SOURCES src/ping_server.cc
    LINK_LIBRARIES ${LIBTRANSPORT_LIBRARIES} ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
    INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${HICN_UTILS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    LINK_FLAGS ${LINK_FLAGS}
  )

  build_executable(hicn-ping-client
    SOURCES src/ping_client.cc
    LINK_LIBRARIES ${LIBTRANSPORT_LIBRARIES} ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
    INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${HICN_UTILS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    LINK_FLAGS ${LINK_FLAGS}
  )
endif ()
