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

list(APPEND LIBHICN_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn.h
  ${CMAKE_CURRENT_SOURCE_DIR}/base.h
  ${CMAKE_CURRENT_SOURCE_DIR}/common.h
  ${CMAKE_CURRENT_SOURCE_DIR}/compat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/header.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.h
  ${CMAKE_CURRENT_SOURCE_DIR}/name.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ops.h
)

list(APPEND LIBHICN_HEADER_FILES_PROTOCOL
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ah.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/icmp.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/icmprd.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ipv4.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ipv6.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/tcp.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/udp.h
)

list(APPEND LIBHICN_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/compat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/error.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.c
  ${CMAKE_CURRENT_SOURCE_DIR}/name.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ops.c
  ${CMAKE_CURRENT_SOURCE_DIR}/common.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ah.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/icmp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ipv4.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/ipv6.c
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol/tcp.c
)

set (COMPILER_DEFINITIONS "-DWITH_MAPME")

include(BuildMacros)
include(WindowsMacros)

if (ANDROID_API)
  build_library(${LIBHICN}
    STATIC
    SOURCES ${LIBHICN_SOURCE_FILES} ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL}
    COMPONENT lib${LIBHICN}
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..
    DEFINITIONS ${COMPILER_DEFINITIONS}
    INSTALL_ROOT_DIR hicn
    INSTALL_HEADERS ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL}
    LINK_LIBRARIES ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
  )
else ()
  build_library(${LIBHICN}
    SHARED STATIC
    SOURCES ${LIBHICN_SOURCE_FILES} ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL}
    COMPONENT lib${LIBHICN}
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..
    DEFINITIONS ${COMPILER_DEFINITIONS}
    INSTALL_ROOT_DIR hicn
    INSTALL_HEADERS ${LIBHICN_HEADER_FILES} ${LIBHICN_HEADER_FILES_PROTOCOL}
    LINK_LIBRARIES ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
  )
endif ()
add_custom_command(TARGET ${LIBHICN_STATIC} PRE_BUILD
  COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/hicn
)

add_custom_command(TARGET ${LIBHICN_STATIC} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/hicn/
  COMMAND ${CMAKE_COMMAND} -E copy ${LIBHICN_HEADER_FILES} ${CMAKE_BINARY_DIR}/hicn/
)

add_custom_command(TARGET ${LIBHICN_STATIC} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/hicn/protocol
  COMMAND ${CMAKE_COMMAND} -E copy ${LIBHICN_HEADER_FILES_PROTOCOL} ${CMAKE_BINARY_DIR}/hicn/protocol
)

set(HICN_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR} ""
  CACHE INTERNAL
  "" FORCE
)

# install(FILES ${LIBHICN_HEADER_FILES} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/hicn COMPONENT libhicn)
# install(FILES ${LIBHICN_HEADER_FILES_PROTOCOL} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/hicn/protocol COMPONENT libhicn)
