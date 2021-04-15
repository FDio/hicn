# Copyright (c) 2019 Cisco and/or its affiliates.
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

set(SAFE_VAPI safe_vapi CACHE INTERNAL "" FORCE)
set(SAFE_VAPI_SHARED ${SAFE_VAPI}.shared CACHE INTERNAL "" FORCE)
set(SAFE_VAPI_STATIC ${SAFE_VAPI}.static CACHE INTERNAL "" FORCE)

# Dependencies

find_package(Vpp REQUIRED)

list(APPEND HEADER_FILES
     ${CMAKE_CURRENT_SOURCE_DIR}/include/vapi/vapi_safe.h
)

list(APPEND SOURCE_FILES
     ${CMAKE_CURRENT_SOURCE_DIR}/vapi_safe.c
)

set (LIBRARIES
    ${VPP_LIBRARY_VAPICLIENT})

list (APPEND INCLUDE_DIRS
     ${VPP_INCLUDE_DIR}
     ${CMAKE_CURRENT_SOURCE_DIR}/include)

build_library(${SAFE_VAPI}
    SHARED STATIC
    SOURCES ${SOURCE_FILES} ${HEADER_FILES}
    INSTALL_HEADERS ${HEADER_FILES}
    LINK_LIBRARIES ${LIBRARIES}
    COMPONENT ${HICN_PLUGIN}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    HEADER_ROOT_DIR /
    DEFINITIONS ${COMPILER_DEFINITIONS}
  )

set(SAFE_VAPI_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  "" CACHE INTERNAL
  "" FORCE
)

set(SAFE_VAPI_LIBRARIES
  ${SAFE_VAPI_SHARED}
  "" CACHE INTERNAL
  "" FORCE
)

