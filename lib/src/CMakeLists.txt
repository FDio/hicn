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
# Source and Header files
##############################################################
list(APPEND LIBHICN_SOURCE_FILES
  common.c
  compat.c
  error.c
  face.c
  mapme.c
  name.c
  ops.c
  policy.c
  strategy.c
  protocol/ah.c
  protocol/icmp.c
  protocol/ipv4.c
  protocol/ipv6.c
  protocol/tcp.c
  protocol/udp.c
  protocol/new.c
  util/ip_address.c
  util/log.c
  util/pool.c
  util/ring.c
  util/vector.c
)

if (WIN32)
  list(APPEND LIBHICN_SOURCE_FILES
    util/windows/dlfcn.c
  )
endif ()

##############################################################
# Compiler definitions
##############################################################
set (COMPILER_DEFINITIONS
  PUBLIC "-DWITH_MAPME"
  PUBLIC "-DWITH_POLICY"
)

include(BuildMacros)
include(WindowsMacros)

##############################################################
# Build type
##############################################################
set (BUILD_TYPES "STATIC")

if (NOT DISABLE_SHARED_LIBRARIES)
  list(APPEND BUILD_TYPES
    "SHARED"
  )
endif()


##############################################################
# Compiler Options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)


##############################################################
# Link libraries
##############################################################
if (WIN32)
  list(APPEND LIBRARIES
    PRIVATE ${WSOCK32_LIBRARY}
    PRIVATE ${WS2_32_LIBRARY}
  )
endif ()


##############################################################
# Build library
##############################################################
build_library(${LIBHICN}
  ${BUILD_TYPES}
  SOURCES ${LIBHICN_SOURCE_FILES}
  COMPONENT ${LIBHICN_COMPONENT}
  INCLUDE_DIRS
    PUBLIC
      $<BUILD_INTERFACE:${Libhicn_INCLUDE_DIRS}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
      $<BUILD_INTERFACE:${THIRD_PARTY_INCLUDE_DIRS}>
  DEFINITIONS ${COMPILER_DEFINITIONS}
  INSTALL_HEADERS ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL} ${LIBHICN_HEADER_FILES_UTIL}
  DEPENDS ${THIRD_PARTY_DEPENDENCIES}
  LINK_LIBRARIES
    PRIVATE ${WSOCK32_LIBRARY}
    PRIVATE ${WS2_32_LIBRARY}
    PUBLIC ${THIRD_PARTY_LIBRARIES}
  VERSION ${CURRENT_VERSION}
  EXPORT_NAME ${LIBHICN_COMPONENT}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)

##############################################################
# Unit tests
##############################################################
if (${BUILD_TESTS})
  add_subdirectory(test)
endif()


##############################################################
# Cmake config files
##############################################################
create_cmake_config (
  ${LIBHICN_COMPONENT}
  INCLUDE_DIRS ${HICN_INCLUDE_DIRS}
  VERSION ${CURRENT_VERSION}
  COMPONENT ${LIBHICN_COMPONENT}
  NAMESPACE hicn
)
