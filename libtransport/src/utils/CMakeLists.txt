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

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/string_tokenizer.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/uri.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/log.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/membuf.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/content_store.cc
)


list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/event_reactor.h
  ${CMAKE_CURRENT_SOURCE_DIR}/min_filter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/stream_buffer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/suffix_strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/event_thread.h
  ${CMAKE_CURRENT_SOURCE_DIR}/content_store.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deadline_timer.h
)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/epoll_event_reactor.h
    ${CMAKE_CURRENT_SOURCE_DIR}/fd_deadline_timer.h
  )

  list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/epoll_event_reactor.cc
  )
endif()

if(NOT WIN32)
  list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/daemonizator.cc
  )
endif()

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
