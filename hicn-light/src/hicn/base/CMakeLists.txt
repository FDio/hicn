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
  ${CMAKE_CURRENT_SOURCE_DIR}/address.h
  ${CMAKE_CURRENT_SOURCE_DIR}/address_pair.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bitmap.h
  ${CMAKE_CURRENT_SOURCE_DIR}/common.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connection_table.h
  ${CMAKE_CURRENT_SOURCE_DIR}/khash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/listener_table.h
  ${CMAKE_CURRENT_SOURCE_DIR}/msgbuf.h
  ${CMAKE_CURRENT_SOURCE_DIR}/packet_cache.h
  ${CMAKE_CURRENT_SOURCE_DIR}/prefix_stats.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/vector.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/address.c
  ${CMAKE_CURRENT_SOURCE_DIR}/address_pair.c
  ${CMAKE_CURRENT_SOURCE_DIR}/connection_table.c
  ${CMAKE_CURRENT_SOURCE_DIR}/listener_table.c
  ${CMAKE_CURRENT_SOURCE_DIR}/msgbuf.c
  ${CMAKE_CURRENT_SOURCE_DIR}/packet_cache.c
  ${CMAKE_CURRENT_SOURCE_DIR}/prefix_stats.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pool.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy.c
  ${CMAKE_CURRENT_SOURCE_DIR}/vector.c
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)

set(TO_INSTALL_HEADER_FILES
  ${TO_INSTALL_HEADER_FILES}
  ${HEADER_FILES}
  PARENT_SCOPE
)
