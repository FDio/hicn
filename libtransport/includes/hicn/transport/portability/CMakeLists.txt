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
  ${CMAKE_CURRENT_SOURCE_DIR}/c_portability.h
  ${CMAKE_CURRENT_SOURCE_DIR}/portability.h
)

list(APPEND SOURCE_FILES
  ""
)

if(WIN32)
  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/win_portability.h
  )
endif()

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)