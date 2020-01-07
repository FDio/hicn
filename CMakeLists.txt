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

## Enabled components
option(BUILD_LIBHICN "Build the hicn core library" ON)
option(BUILD_HICNLIGHT "Build the hicn light forwarder" ON)
option(BUILD_LIBTRANSPORT "Build the hicn transport library" ON)
option(BUILD_UTILS "Build the hicn utils" ON)
option(BUILD_APPS "Build the hicn apps" OFF)
option(BUILD_CTRL "Build the hicn control tools" ON)
option(BUILD_HICNPLUGIN "Build the hicn vpp plugin" OFF)
option(BUILD_SYSREPOPLUGIN "Build the sysrepo plugin" OFF)
option(BUILD_EXTRAS "Build external projects." OFF)

if ((BUILD_APPS OR BUILD_UTILS) AND NOT BUILD_LIBTRANSPORT)
  message(STATUS "Libhicntransport required. Enabled by default.")
  set (BUILD_LIBTRANSPORT ON)
endif()

if (BUILD_SYSREPOPLUGIN AND NOT BUILD_HICNPLUGIN)
  message(STATUS "Hicn-plugin required. Enabled by default.")
  set (BUILD_HICNPLUGIN ON)
endif()

if ((BUILD_HICNLIGHT OR
     BUILD_LIBTRANSPORT OR
     BUILD_UTILS OR
     BUILD_APPS OR
     BUILD_CTRL OR
     BUILD_HICNPLUGIN OR
     BUILD_SYSREPOPLUGIN)
     AND NOT BUILD_LIBHICN)
  message(STATUS "Libhicn required. Enabled by default.")
  set(BUILD_LIBHICN ON)
endif()

list(APPEND dir_options
  BUILD_LIBHICN
  BUILD_HICNLIGHT
  BUILD_HICNPLUGIN
  BUILD_CTRL
  BUILD_LIBTRANSPORT
  BUILD_UTILS
  BUILD_APPS
  BUILD_SYSREPOPLUGIN
  BUILD_EXTRAS
)

set(BUILD_LIBHICN_DIR lib)
set(BUILD_HICNLIGHT_DIR hicn-light)
set(BUILD_LIBTRANSPORT_DIR libtransport)
set(BUILD_UTILS_DIR utils)
set(BUILD_APPS_DIR apps)
set(BUILD_CTRL_DIR ctrl)
set(BUILD_HICNPLUGIN_DIR hicn-plugin)
set(BUILD_SYSREPOPLUGIN_DIR ctrl/sysrepo-plugins)
set(BUILD_EXTRAS_DIR extras/)

## Add enabled components
foreach (opt ${dir_options})
  if (${opt})
    list(APPEND subdirs
      ${${opt}_DIR}
    )
  endif()
endforeach()

if (NOT WIN32)
  add_compile_options(-Wall -Werror)
endif ()

message(STATUS "Building the following subprojects: ${subdirs}")

foreach(dir ${subdirs})
  add_subdirectory(${dir})
endforeach()

include(Packager)
make_packages()