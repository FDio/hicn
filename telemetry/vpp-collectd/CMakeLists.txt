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

project(hicn-collectd-plugins)


##############################################################
# CMake Modules
##############################################################
set(CMAKE_MODULE_PATH
	${CMAKE_MODULE_PATH}
	${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules/)


##############################################################
# Dependencies
##############################################################
find_package(Vpp ${VPP_DEFAULT_VERSION} REQUIRED)
find_package(Collectd ${COLLECTD_DEFAULT_VERSION} REQUIRED)


##############################################################
# Libs and bins names
##############################################################
set(COLLECTD_PLUGINS hicn-collectd-plugins)


##############################################################
# Packaging
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)


##############################################################
# Compiler Options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)


##############################################################
# Subdirectories
##############################################################
add_subdirectory(vpp)
add_subdirectory(vpp-hicn)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
	make_packages()
endif()
