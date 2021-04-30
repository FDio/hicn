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
project(router-plugin)

include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules/"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/"
)

set (CMAKE_C_STANDARD 11)

include (Packaging)

set(HICN_EXTRA_PLUGIN hicn-router-plugin)

# Dependencies

find_package(Vpp REQUIRED)

include_directories(${VPP_INCLUDE_DIR})

set(HICN_EXTRA_PLUGIN_SOURCE_FILES
  rtinject/tap_inject.c
  rtinject/tap_inject_netlink.c
  rtinject/tap_inject_node.c
  rtinject/tap_inject_tap.c
  devices/rtnetlink/mapper.c
  devices/rtnetlink/netns.c
  devices/rtnetlink/rtnl.c
)

set(HICN_EXTRA_PLUGIN_HEADER_FILES
  devices/rtnetlink/mapper.h
  devices/rtnetlink/netns.h
  devices/rtnetlink/rtnl.h
)

if (NOT VPP_HOME)
  set(VPP_HOME /usr)
endif()

if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release")
endif (NOT CMAKE_BUILD_TYPE)

SET(EXTRA_INSTALL_PREFIX
  ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
  CACHE STRING "extra_install_prefix"
)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
   set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall -march=native -O3 -g")
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
   set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -march=native -O0 -g")
   add_definitions(-DCLIB_DEBUG -fPIC -fstack-protector-all)
endif()

include_directories(SYSTEM)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEXTRA_VPP_PLUGIN=1")

add_library(hicn_router_plugin SHARED
  ${HICN_EXTRA_PLUGIN_SOURCE_FILES}
)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins)

set(VPP_INSTALL_PLUGIN ${EXTRA_INSTALL_PREFIX}/vpp_plugins)

set_target_properties(hicn_router_plugin
  PROPERTIES
  LINKER_LANGUAGE C
  INSTALL_RPATH ${VPP_INSTALL_PLUGIN}
  PREFIX ""
  LIBRARY_OUTPUT_NAME "hicn_router"
)

install(DIRECTORY
  DESTINATION ${VPP_INSTALL_PLUGIN}
  COMPONENT ${HICN_EXTRA_PLUGIN}
)

install(TARGETS hicn_router_plugin
  DESTINATION
  ${VPP_INSTALL_PLUGIN}
  COMPONENT ${HICN_EXTRA_PLUGIN}
)
