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

find_library(NETWORK_LIBRARY Network)
if (NOT NETWORK_LIBRARY)
    message(FATAL_ERROR "NetworkFramework not found")
endif()

list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/network_framework.h
)

list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/network_framework.c
)

list(APPEND INCLUDE_DIRS
)

list(APPEND LIBRARIES
    ${NETWORK_LIBRARY}
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
set(INCLUDE_DIRS ${INCLUDE_DIRS} PARENT_SCOPE)
set(LIBRARIES    ${LIBRARIES}    PARENT_SCOPE)
