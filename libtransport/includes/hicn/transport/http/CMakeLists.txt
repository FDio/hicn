# Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
  ${CMAKE_CURRENT_SOURCE_DIR}/client_connection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/request.h
  ${CMAKE_CURRENT_SOURCE_DIR}/default_values.h
  ${CMAKE_CURRENT_SOURCE_DIR}/facade.h
  ${CMAKE_CURRENT_SOURCE_DIR}/response.h
  ${CMAKE_CURRENT_SOURCE_DIR}/message.h
)

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)