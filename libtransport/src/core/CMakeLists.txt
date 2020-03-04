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

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/facade.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_inline.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_format_fixed.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_format.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pending_interest.h
  ${CMAKE_CURRENT_SOURCE_DIR}/portal.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tcp_socket_connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_forwarder_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/vpp_forwarder_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memif_connector.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/content_object.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/interest.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/packet.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/name.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/prefix.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/tcp_socket_connector.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_connector.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_forwarder_interface.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_format_fixed.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/connector.cc
)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  if (BUILD_WITH_VPP OR BUILD_HICNPLUGIN)
    list(APPEND HEADER_FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/vpp_forwarder_interface.h
      ${CMAKE_CURRENT_SOURCE_DIR}/memif_connector.h
      ${CMAKE_CURRENT_SOURCE_DIR}/hicn_vapi.h
      ${CMAKE_CURRENT_SOURCE_DIR}/memif_vapi.h
    )

    list(APPEND SOURCE_FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/vpp_forwarder_interface.cc
      ${CMAKE_CURRENT_SOURCE_DIR}/memif_connector.cc
      ${CMAKE_CURRENT_SOURCE_DIR}/hicn_vapi.c
      ${CMAKE_CURRENT_SOURCE_DIR}/memif_vapi.c
    )
  endif()

  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/raw_socket_connector.h
    ${CMAKE_CURRENT_SOURCE_DIR}/raw_socket_interface.h
  )

  list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/raw_socket_connector.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/raw_socket_interface.cc
  )
endif()

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)