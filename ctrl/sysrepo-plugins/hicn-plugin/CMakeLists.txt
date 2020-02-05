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

cmake_minimum_required(VERSION 2.8)

# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../../../cmake/Modules"
     "${CMAKE_CURRENT_LIST_DIR}/../cmake/Modules"
)

# plugins sources
set(SOURCE_FILES
    plugin/ietf/ietf_interface.c
    plugin/model/hicn_model.c
    plugin/model/tlock.c
    plugin/hicn_vpp_comm.c
    plugin/hicn_plugin.c
)

list(APPEND SYSREPO_PLUGIN_INCLUDE_DIRS
    ${VPP_INCLUDE_DIRS}
    ${HICNPLUGIN_INCLUDE_DIRS}
)

list(APPEND LIBRARIES
    ${SYSREPO_LIBRARIES}
    ${VPP_LIBRARIES})

build_library(sysrepohicn
    SHARED
    SOURCES ${SOURCE_FILES}
    LINK_LIBRARIES ${LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT hicn-sysrepo-plugin
    INCLUDE_DIRS ${SYSREPO_PLUGIN_INCLUDE_DIRS}
    INSTALL_FULL_PATH_DIR ${SRPD_PLUGINS_PATH}
    DEFINITIONS ${COMPILER_DEFINITIONS}
)