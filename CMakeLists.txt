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

list(APPEND dir_options
  BUILD_LIBHICN
  BUILD_HICNLIGHT
  BUILD_LIBTRANSPORT
  BUILD_UTILS
  BUILD_APPS
  BUILD_CTRL
)

set(BUILD_LIBHICN_DIR lib)
set(BUILD_HICNLIGHT_DIR hicn-light)
set(BUILD_LIBTRANSPORT_DIR libtransport)
set(BUILD_UTILS_DIR utils)
set(BUILD_APPS_DIR apps)
set(BUILD_CTRL_DIR ctrl)
set(BUILD_HICNPLUGIN_DIR hicn-plugin)
set(BUILD_HICNEXTRAPLUGIN_DIR utils/extras/)

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
set(HICN_CTRL hicn-ctrl)
set(LIBHICN_CTRL hicn-ctrl)
set(HICN_APPS hicn-apps)
set(FACE_MGR facemgr)

if (BUILD_HICNPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  list(APPEND subdirs
    ${BUILD_HICNPLUGIN_DIR}
  )

  list(APPEND HICN_BINARY_API_INCLUDE_DIRS
    ${PROJECT_BINARY_DIR}/hicn-plugin
    ${PROJECT_BINARY_DIR}/hicn-plugin/vpp_plugins
  )

  set(LIBTRANSPORT ${LIBTRANSPORT}-memif)
endif()

if (BUILD_HICNEXTRAPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  list(APPEND subdirs
    ${BUILD_HICNEXTRAPLUGIN_DIR}
  )
endif()

## Libraries targets
set(LIBHICN_SHARED ${LIBHICN}.shared)
set(LIBTRANSPORT_SHARED ${LIBTRANSPORT}.shared)
set(LIBHICN_CTRL_SHARED ${LIBHICN_CTRL}.shared)

set(LIBHICN_STATIC ${LIBHICN}.static)
set(LIBTRANSPORT_STATIC ${LIBTRANSPORT}.static)
set(LIBHICN_CTRL_STATIC ${LIBHICN_CTRL}.static)

## HEADER FILES
set(HICN_INCLUDE_DIRS ${PROJECT_BINARY_DIR}/lib "" CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/libtransport/src "" CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/ctrl/libhicnctrl/includes  "" CACHE INTERNAL "" FORCE)

if (NOT WIN32)
  add_compile_options(-Wall -Werror)
endif ()

message(STATUS "Building the following subprojects: ${subdirs}")

foreach(dir ${subdirs})
  add_subdirectory(${dir})
endforeach()

include(Packager)
make_packages()
