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
  ${CMAKE_CURRENT_SOURCE_DIR}/array.h
  ${CMAKE_CURRENT_SOURCE_DIR}/string_tokenizer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/uri.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chrono_typedefs.h
  ${CMAKE_CURRENT_SOURCE_DIR}/branch_prediction.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ring_buffer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/literals.h
  ${CMAKE_CURRENT_SOURCE_DIR}/conversions.h
  ${CMAKE_CURRENT_SOURCE_DIR}/linux.h
  ${CMAKE_CURRENT_SOURCE_DIR}/log.h
  ${CMAKE_CURRENT_SOURCE_DIR}/object_pool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/membuf.h
  ${CMAKE_CURRENT_SOURCE_DIR}/spinlock.h
)

if(NOT WIN32)
  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/daemonizator.h
  )
endif()

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)