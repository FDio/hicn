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

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/array.h
  ${CMAKE_CURRENT_SOURCE_DIR}/string_tokenizer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/uri.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chrono_typedefs.h
  ${CMAKE_CURRENT_SOURCE_DIR}/branch_prediction.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ring_buffer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_quality_score.h
  ${CMAKE_CURRENT_SOURCE_DIR}/literals.h
  ${CMAKE_CURRENT_SOURCE_DIR}/conversions.h
  ${CMAKE_CURRENT_SOURCE_DIR}/linux.h
  ${CMAKE_CURRENT_SOURCE_DIR}/log.h
  ${CMAKE_CURRENT_SOURCE_DIR}/object_pool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/membuf.h
  ${CMAKE_CURRENT_SOURCE_DIR}/spinlock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fixed_block_allocator.h
  ${CMAKE_CURRENT_SOURCE_DIR}/event_thread.h
  ${CMAKE_CURRENT_SOURCE_DIR}/string_utils.h
  ${CMAKE_CURRENT_SOURCE_DIR}/file.h
  ${CMAKE_CURRENT_SOURCE_DIR}/shared_ptr_utils.h
  ${CMAKE_CURRENT_SOURCE_DIR}/move_wrapper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/noncopyable.h
  ${CMAKE_CURRENT_SOURCE_DIR}/singleton.h
)

if(NOT WIN32)
  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/daemonizator.h
  )
endif()

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)