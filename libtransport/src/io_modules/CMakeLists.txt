# Copyright (c) 2021 Cisco and/or its affiliates.
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

if ((${CMAKE_SYSTEM_NAME} MATCHES Android) OR (${CMAKE_SYSTEM_NAME} MATCHES Windows) OR ({CMAKE_SYSTEM_NAME} MATCHES iOS))
  list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/udp/hicn_forwarder_module.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/udp/udp_socket_connector.cc
  )

  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/udp/hicn_forwarder_module.h
    ${CMAKE_CURRENT_SOURCE_DIR}/udp/udp_socket_connector.h
  )

  set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
  set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
else ()
  add_subdirectory(udp)
  add_subdirectory(loopback)
  add_subdirectory(forwarder)

  if (__vpp__)
    add_subdirectory(memif)
  endif()
endif()