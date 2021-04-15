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


list(APPEND MODULE_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/endpoint.h
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder_module.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnel_listener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/global_counter.h
)

list(APPEND MODULE_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder_module.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnel_listener.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnel.cc
)

build_module(forwarder_module
    SHARED
    SOURCES ${MODULE_SOURCE_FILES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT lib${LIBTRANSPORT}
    INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS} ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILE_FLAGS}
)
