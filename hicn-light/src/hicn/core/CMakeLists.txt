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
  ${CMAKE_CURRENT_SOURCE_DIR}/ticks.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fib_entry.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fib_entry_list.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fib.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.h
  ${CMAKE_CURRENT_SOURCE_DIR}/message.h
  ${CMAKE_CURRENT_SOURCE_DIR}/messagePacketType.h
# ${CMAKE_CURRENT_SOURCE_DIR}/system.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wldr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/messageHandler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/nameBitvector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/name.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/fib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/fib_entry.c
  ${CMAKE_CURRENT_SOURCE_DIR}/fib_entry_list.c
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.c
  ${CMAKE_CURRENT_SOURCE_DIR}/message.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wldr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/nameBitvector.c
  ${CMAKE_CURRENT_SOURCE_DIR}/name.c
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)

set(TO_INSTALL_HEADER_FILES
  ${TO_INSTALL_HEADER_FILES}
  ${HEADER_FILES}
  PARENT_SCOPE
)
