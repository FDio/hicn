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

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(hicn-fdio)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

## Enabled components
option(BUILD_LIBHICN "Build the hicn core library" ON)
option(BUILD_HICNLIGHT "Build the hicn light forwarder" ON)
option(BUILD_LIBTRANSPORT "Build the hicn transport library" ON)
option(BUILD_APPS "Build the hicn apps" ON)
if (NOT WIN32)
  option(BUILD_CTRL "Build the hicn control tools" ON)
  option(DISABLE_SHARED_LIBRARIES "Disable shared libraries" OFF)
else ()
  option(BUILD_CTRL "Build the hicn control tools" OFF)
  option(DISABLE_SHARED_LIBRARIES "Disable shared libraries" ON)
endif ()
option(BUILD_HICNPLUGIN "Build the hicn vpp plugin" OFF)
option(BUILD_SYSREPOPLUGIN "Build the sysrepo plugin" OFF)
option(BUILD_EXTRAS "Build external projects" OFF)
option(BUILD_TELEMETRY "Build telemetry projects" OFF)
option(BUILD_TESTS "Build unit tests" OFF)
option(DISABLE_EXECUTABLES "Disable executables" OFF)

if (BUILD_APPS AND NOT BUILD_LIBTRANSPORT)
  message(STATUS "Libhicntransport required. Enabled by default.")
  set (BUILD_LIBTRANSPORT ON)
endif()

if (BUILD_SYSREPOPLUGIN AND NOT BUILD_HICNPLUGIN)
  message(STATUS "Hicn-plugin required. Enabled by default.")
  set (BUILD_HICNPLUGIN ON)
endif()

if ((BUILD_HICNLIGHT OR
     BUILD_LIBTRANSPORT OR
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
  BUILD_APPS
  BUILD_SYSREPOPLUGIN
  BUILD_EXTRAS
  BUILD_TELEMETRY
)

set(BUILD_LIBHICN_DIR lib)
set(BUILD_HICNLIGHT_DIR hicn-light)
set(BUILD_LIBTRANSPORT_DIR libtransport)
set(BUILD_APPS_DIR apps)
set(BUILD_CTRL_DIR ctrl)
set(BUILD_HICNPLUGIN_DIR hicn-plugin)
set(BUILD_SYSREPOPLUGIN_DIR ctrl/sysrepo-plugins)
set(BUILD_EXTRAS_DIR extras/)
set(BUILD_TELEMETRY_DIR telemetry)

## Add enabled components
foreach (opt ${dir_options})
  if (${opt})
    list(APPEND subdirs
      ${${opt}_DIR}
    )
  endif()
endforeach()

# Add unit tests
if (BUILD_TESTS)
  message(STATUS "Tests enabled.")
  include (GTestImport)

  if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
    include (GoogleTest)
  else()
    include (CTest)
  endif()
endif()

message(STATUS "Building the following subprojects: ${subdirs}")

foreach(dir ${subdirs})
  add_subdirectory(${dir})
endforeach()

add_subdirectory(docs/doxygen)

include(Packager)
make_packages()