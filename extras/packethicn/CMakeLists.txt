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

cmake_minimum_required(VERSION 3.5)
cmake_policy(SET CMP0048 NEW)

project(packethicn VERSION 0.0.1 DESCRIPTION "hICN protocol plugin" LANGUAGES C)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules
)

set(PACKETHICN packethicn)

find_package(Wireshark CONFIG REQUIRED)

MATH(EXPR Wireshark_PATCH_NEXT_VERSION "${Wireshark_PATCH_VERSION}+1")
set(Wireshark_NEXT_VERSION ${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}.${Wireshark_PATCH_NEXT_VERSION})

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(Libhicn REQUIRED)
else()
  if (DISABLE_SHARED_LIBRARIES)
    if (WIN32)
      set(HICN_LIBRARIES ${LIBHICN_STATIC})
    else()
      set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    endif()
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
    )
  else()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
    )
  endif()
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
  message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

set(COMPILER_DEFINITIONS -DVERSION=\"${PROJECT_VERSION}\")

set(SOURCE_FILES
  packet-hicn.c
)

list(APPEND PACKETHICN_INCLUDE_DIRS
  ${HICN_INCLUDE_DIRS}
)

list(APPEND LIBRARIES
  ${HICN_LIBRARIES}
  epan
)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(LIBHICN hicn CACHE INTERNAL "" FORCE)
endif()

include(Packaging)
include(BuildMacros)

build_library(${PACKETHICN}
  MODULE
  SOURCES ${SOURCE_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${PACKETHICN}
  INCLUDE_DIRS ${PACKETHICN_INCLUDE_DIRS}
  INSTALL_FULL_PATH_DIR ${Wireshark_PLUGIN_INSTALL_DIR}/epan
  DEFINITIONS ${COMPILER_DEFINITIONS}
  EMPTY_PREFIX true
)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(Packager)
    make_packages()
endif()