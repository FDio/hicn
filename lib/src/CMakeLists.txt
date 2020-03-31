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

list(APPEND LIBHICN_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/common.c
  ${CMAKE_CURRENT_SOURCE_DIR}/compat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/error.c
  ${CMAKE_CURRENT_SOURCE_DIR}/face.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.c
  ${CMAKE_CURRENT_SOURCE_DIR}/name.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ops.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ah.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/icmp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ipv4.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ipv6.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/tcp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/util/ip_address.c
  ${CMAKE_CURRENT_SOURCE_DIR}/util/log.c
)

set (COMPILER_DEFINITIONS
    "-DWITH_MAPME"
    "-DWITH_POLICY"
)

include(BuildMacros)
include(WindowsMacros)

if (DISABLE_SHARED_LIBRARIES)
  build_library(${LIBHICN}
    STATIC
    SOURCES ${LIBHICN_SOURCE_FILES} ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL} ${LIBHICN_HEADER_FILES_UTIL}
    COMPONENT lib${LIBHICN}
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../includes
    DEFINITIONS ${COMPILER_DEFINITIONS}
    INSTALL_ROOT_DIR hicn
    INSTALL_HEADERS ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL} ${LIBHICN_HEADER_FILES_UTIL}
    LINK_LIBRARIES ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
  )
else ()
  build_library(${LIBHICN}
    SHARED STATIC
    SOURCES ${LIBHICN_SOURCE_FILES} ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL} ${LIBHICN_HEADER_FILES_UTIL}
    COMPONENT lib${LIBHICN}
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../includes
    DEFINITIONS ${COMPILER_DEFINITIONS}
    INSTALL_ROOT_DIR hicn
    INSTALL_HEADERS ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL} ${LIBHICN_HEADER_FILES_UTIL}
    LINK_LIBRARIES ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
  )
endif ()
