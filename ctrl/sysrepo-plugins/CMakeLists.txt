#
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
#

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(hicn_sysrepo_plugin)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
"${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules"
)

include(GNUInstallDirs)
include(BuildMacros)

find_package(PkgConfig REQUIRED)
find_package(Sysrepo REQUIRED)

if (NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  message(FATAL_ERROR "Sysrepo plugin supported only on Linux systems")
endif()

if (NOT SRPD_PLUGINS_PATH)
  if (PKG_CONFIG_FOUND)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=SRPD_PLUGINS_PATH" "libsysrepo" OUTPUT_VARIABLE SRPD_PLUGINS_PATH)
    string(STRIP ${SRPD_PLUGINS_PATH} SRPD_PLUGINS_PATH)
  endif()
endif()

if (NOT SRPD_PLUGINS_PATH)
  message(FATAL_ERROR "Cannot get sysrepo plugins directory due to missing pkg-config, set SRPD_PLUGINS_PATH manually.")
endif()

find_package(Vpp REQUIRED)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(HicnPlugin REQUIRED)
else()
  list(APPEND DEPENDENCIES
    hicn_plugin
  )
endif()

add_subdirectory(hicn-plugin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/yang/hicn/hicn.yang
        ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf/iana-if-type@2014-05-08.yang
        ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf/ietf-interfaces.yang
        ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf/ietf-ip@2014-06-16.yang
        ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf/ietf-yang-types@2013-07-15.yang
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/modules_yang/
      COMPONENT hicn-sysrepo-plugin)


include(Packaging)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(Packager)
    make_packages()
endif()
