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

## Target names
set(LIBHICN hicn)
set(LIBHICN_SHARED hicn.shared)
set(LIBHICN_LIGHT hicn-light)
set(HICN_LIGHT_CONTROL hicnLightControl)
set(HICN_LIGHT_DAEMON hicnLightDaemon)
set(HICN_PLUGIN hicn-plugin)
set(LIBTRANSPORT hicntransport)
set(LIBTRANSPORT_SHARED hicntransport.shared)
set(HICN_UTILS hicn-utils)

## HEADER FILES
set(LIBHICN_HEADER_FILES)
set(LIBHICN_LIGHT_HEADER_FILES)
set(LIBTRANSPORT_HEADER_FILES)

set(SUBDIRS lib hicn-light libtransport utils)

add_compile_options(-Wall -Werror)

if (BUILD_VPP_PLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" )
  list(APPEND SUBDIRS
    hicn-plugin
  )

  list(APPEND HICN_BINARY_API_INCLUDE_DIRS
    ${PROJECT_BINARY_DIR}/hicn-plugin
    ${PROJECT_BINARY_DIR}/hicn-plugin/vpp_plugins
  )
endif()

foreach(dir ${SUBDIRS})
  add_subdirectory(${dir})
endforeach()

include(Packager)
make_packages()