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
project(telemetry)


##############################################################
# C Standard
##############################################################
set(CMAKE_C_STANDARD 11)


##############################################################
# Cmake modules
##############################################################
include("${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake")
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules
)


##############################################################
# Libs and Bins names
##############################################################
set(COLLECTD_PLUGINS hicn-collectd-plugins CACHE INTERNAL "" FORCE)
set(HICN_LIGHT_TELEMETRY hicn_light)
set(KAFKA_TELEMETRY write_kafka_line_protocol)
set(VPP_TELEMETRY vpp)
set(VPP_HICN_TELEMETRY vpp_hicn)


##############################################################
# Dependencies and third party libs
##############################################################
find_package(Collectd ${COLLECTD_DEFAULT_VERSION} REQUIRED)
add_subdirectory(third-party)


##############################################################
# Check if building as subproject or as root project
##############################################################
if(NOT (CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR) AND
  NOT (BUILD_HICNPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux"))
  return()
endif()
include(CommonSetup)

# Include config.h in all collectd plugins
set(COLLECTD_COMPILER_OPTIONS -include config.h)

# ##############################################################
# # Packaging and versioning
# ##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)


##############################################################
# Subdirectories
##############################################################
add_subdirectory(hicn-light-collectd)
add_subdirectory(kafka-collectd)
add_subdirectory(vpp-collectd)