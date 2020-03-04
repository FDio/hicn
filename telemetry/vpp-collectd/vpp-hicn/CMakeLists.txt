# Copyright (c) 2020 Cisco and/or its affiliates.
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

# Dependencies
find_package(Collectd REQUIRED)
find_package(Vpp REQUIRED)

if(${CMAKE_SOURCE_DIR}/vpp-collectd STREQUAL ${PROJECT_SOURCE_DIR})
   message (STATUS "not compiling in the same folder")
  find_package(HicnPlugin REQUIRED)
  find_package(VapiSafe REQUIRED)
else()
  message (STATUS "compiling in the same folder")
  list(APPEND DEPENDENCIES
    hicn_plugin
  )
endif()

list(APPEND SOURCE_FILES
     ${CMAKE_CURRENT_SOURCE_DIR}/vpp_hicn.c
)

list (APPEND INCLUDE_DIRS
    ${COLLECTD_INCLUDE_DIRS}
    ${HICNPLUGIN_INCLUDE_DIRS}
    ${SAFE_VAPI_INCLUDE_DIRS}
    ${VPP_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR})

list (APPEND LIBRARIES
    ${VPP_LIBRARY_VAPICLIENT}
    ${SAFE_VAPI_LIBRARIES})

build_library(vpp_hicn
    SHARED
    SOURCES ${SOURCE_FILES}
    LINK_LIBRARIES ${LIBRARIES}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    INSTALL_FULL_PATH_DIR ${CMAKE_INSTALL_PREFIX}/lib/collectd
    COMPONENT "${COLLECTD_PLUGINS}"
    DEPENDS ${DEPENDENCIES}
    EMPTY_PREFIX true
  )
