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
option(BUILD_HICNEXTRAPLUGIN "Build the hicn extra plugin" OFF)
option(BUILD_SYSREPOPLUGIN "Build the sysrepo plugin" OFF)
option(BUILD_SYSREPOP "Build the sysrepo plugin" OFF)
option(BUILD_LIBYANG "Build the sysrepo plugin" OFF)

option(WITH_ANDROID_CLI "Build for Android CLI" OFF)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Android" AND WITH_ANDROID_CLI)
  message("Building for Android CLI")
  set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -DWITH_ANDROID_CLI)
endif()

list(APPEND dir_options
  BUILD_LIBHICN
  BUILD_HICNLIGHT
  BUILD_HICNPLUGIN
  BUILD_LIBTRANSPORT
  BUILD_UTILS
  BUILD_APPS
  BUILD_CTRL
  BUILD_HICNEXTRAPLUGIN
  BUILD_SYSREPOPLUGIN
  BUILD_SYSREPO
  BUILD_LIBYANG
  BUILD_LIBMEMIF
)

set(BUILD_LIBHICN_DIR lib)
set(BUILD_HICNLIGHT_DIR hicn-light)
set(BUILD_LIBTRANSPORT_DIR libtransport)
set(BUILD_UTILS_DIR utils)
set(BUILD_APPS_DIR apps)
set(BUILD_CTRL_DIR ctrl)
set(BUILD_HICNPLUGIN_DIR hicn-plugin)
set(BUILD_SYSREPOPLUGIN_DIR ctrl/sysrepo-plugins)
set(BUILD_SYSREPO_DIR extras/sysrepo)
set(BUILD_LIBYANG_DIR extras/libyang)
set(BUILD_HICNEXTRAPLUGIN_DIR extras/hicn-extra-plugin)
set(BUILD_LIBMEMIF_DIR extras/libmemif)


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
set(HICN_LIGHT hicn-light)
set(HICN_LIGHT_CONTROL hicn-light-control)
set(HICN_LIGHT_DAEMON hicn-light-daemon)
set(HICN_PLUGIN hicn-plugin)
set(HICN_EXTRA_PLUGIN hicn-extra-plugin)
set(LIBTRANSPORT hicntransport)
set(HICN_UTILS hicn-utils)
set(HICNCTRL hicnctrl)
set(LIBHICNCTRL hicnctrl)
set(HICN_APPS hicn-apps)
set(LIBFACEMGR facemgr)
set(FACEMGR facemgr)
set(LIBMEMIF memif)

if (BUILD_HICNPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  find_package(Libmemif)

  if (NOT Libmemif_FOUND)
    message(STATUS "Libmemif not found in the system. Building it as external project.")
    list(INSERT subdirs 0
      ${BUILD_LIBMEMIF_DIR}
    )

    unset(LIBMEMIF_INCLUDE_DIRS)
    unset(LIBMEMIF_LIBRARIES)
  endif()

  set(LIBTRANSPORT ${LIBTRANSPORT}-memif)
  set(LIBHICNCTRL ${LIBHICNCTRL}-memif)
endif()

## Libraries targets
set(LIBHICN_SHARED ${LIBHICN}.shared)
set(LIBTRANSPORT_SHARED ${LIBTRANSPORT}.shared)
set(LIBHICNCTRL_SHARED ${LIBHICNCTRL}.shared)
set(LIBMEMIF_SHARED ${LIBMEMIF}.shared)

set(LIBHICN_STATIC ${LIBHICN}.static)
set(LIBTRANSPORT_STATIC ${LIBTRANSPORT}.static)
set(LIBHICNCTRL_STATIC ${LIBHICNCTRL}.static)
set(LIBMEMIF_STATIC ${LIBMEMIF}.static)

## HEADER FILES
set(HICN_INCLUDE_DIRS "" "" CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_INCLUDE_DIRS "" "" CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_INCLUDE_DIRS ""  "" CACHE INTERNAL "" FORCE)

if (NOT WIN32)
  add_compile_options(-Wall -Werror)
endif ()

message(STATUS "Building the following subprojects: ${subdirs}")

foreach(dir ${subdirs})
  add_subdirectory(${dir})
endforeach()

if (NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Android")
include(Packager)
make_packages()
endif()
