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
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder_config.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/http_proxy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/http_session.h
  ${CMAKE_CURRENT_SOURCE_DIR}/http_1x_message_fast_parser.h
  ${CMAKE_CURRENT_SOURCE_DIR}/icn_receiver.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils.h
)

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)

set(LIBPROXY_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/../.. ""
  CACHE INTERNAL
  "" FORCE
)

set(LIBPROXY_TO_INSTALL_HEADER_FILES
  ${HEADER_FILES} ""
  CACHE INTERNAL
  "" FORCE
)

