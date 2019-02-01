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

project(hicn-fdio)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(HICN_INCLUDE_DIRS ${PROJECT_BINARY_DIR}/lib)

## Enabled components
option(BUILD_LIBHICN "Build the hicn core library" ON)
option(BUILD_HICNLIGHT "Build the hicn light forwarder" ON)
option(BUILD_LIBTRANSPORT "Build the hicn transport library" ON)
option(BUILD_UTILS "Build the hicn utils" ON)
option(BUILD_HICNPLUGIN "Build the hicn vpp plugin" OFF)

list(APPEND dir_options
  BUILD_LIBHICN
  BUILD_HICNLIGHT
  BUILD_LIBTRANSPORT
  BUILD_UTILS
)

set(BUILD_LIBHICN_DIR lib)
set(BUILD_HICNLIGHT_DIR hicn-light)
set(BUILD_LIBTRANSPORT_DIR libtransport)
set(BUILD_UTILS_DIR utils)
set(BUILD_HICNPLUGIN_DIR hicn-plugin)

## HEADER FILES
set(LIBHICN_HEADER_FILES)
set(LIBHICN_LIGHT_HEADER_FILES)
set(LIBTRANSPORT_HEADER_FILES)

## Add enabled components
foreach (opt ${dir_options})
  if (${opt})
    list(APPEND subdirs
      ${${opt}_DIR}
    )
  endif()
endforeach()

## Static targets
set(LIBHICN hicn)
set(LIBHICN_LIGHT hicn-light)
set(HICN_LIGHT_CONTROL hicnLightControl)
set(HICN_LIGHT_DAEMON hicnLightDaemon)
set(HICN_PLUGIN hicn-plugin)
set(LIBTRANSPORT hicntransport)
set(HICN_UTILS hicn-utils)

if (BUILD_HICNPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" )
  list(APPEND subdirs
    ${BUILD_HICNPLUGIN_DIR}
  )

  list(APPEND HICN_BINARY_API_INCLUDE_DIRS
    ${PROJECT_BINARY_DIR}/hicn-plugin
    ${PROJECT_BINARY_DIR}/hicn-plugin/vpp_plugins
  )

  set(LIBTRANSPORT ${LIBTRANSPORT}-memif)
  set(HICN_UTILS ${HICN_UTILS}-memif)
endif()

## Shared targets
set(LIBHICN_SHARED ${LIBHICN}.shared)
set(LIBTRANSPORT_SHARED ${LIBTRANSPORT}.shared)

add_compile_options(-Wall -Werror)

message(STATUS "Building the following subprojects: ${subdirs}")

foreach(dir ${subdirs})
  add_subdirectory(${dir})
endforeach()

include(Packager)
make_packages()