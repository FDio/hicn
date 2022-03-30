# Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

##############################################################
# Project and cmake version
##############################################################
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(hicn-plugin)


##############################################################
# Cmake modules
##############################################################
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules/
)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  include(CommonSetup)
endif()


##############################################################
# Libs and Bins names
##############################################################
set(HICN_PLUGIN hicn-plugin CACHE INTERNAL "" FORCE)
set(HICNPLUGIN hicn_plugin CACHE INTERNAL "" FORCE)
set(HICN_API_TEST_PLUGIN hicn_api_test_plugin CACHE INTERNAL "" FORCE)
set(HICNPLUGIN_SHARED ${HICNPLUGIN}.shared CACHE INTERNAL "" FORCE)
set(HICN_API_TEST_PLUGIN_SHARED ${HICN_API_TEST_PLUGIN}.shared CACHE INTERNAL "" FORCE)


##############################################################
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake)


##############################################################
# C Standard
##############################################################
set (CMAKE_C_STANDARD 11)


##############################################################
# Subdirectories
##############################################################
add_subdirectory(includes/vpp_plugins/hicn)
add_subdirectory(src)
add_subdirectory(vapi)
