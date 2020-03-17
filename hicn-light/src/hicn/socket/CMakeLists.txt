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

if (UNIX AND NOT APPLE)
  list(APPEND HEADER_FILES
    socket/api.h
    socket/error.h
    socket/ops.h
  )

  list(APPEND SOURCE_FILES
    socket/api.c
    socket/error.c
    socket/ops_linux.c
  )
endif()

set(TO_INSTALL_HEADER_FILES
  ${TO_INSTALL_HEADER_FILES}
  ${HEADER_FILES}
  PARENT_SCOPE
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
