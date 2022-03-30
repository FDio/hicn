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
cmake_minimum_required (VERSION 3.10 FATAL_ERROR)
project(libhicn C)


##############################################################
# Cmake modules
##############################################################
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  include(CommonSetup)
endif()


##############################################################
# Libs and Bins names
##############################################################
set(LIBHICN hicn CACHE INTERNAL "" FORCE)
set(LIBHICN_COMPONENT lib${LIBHICN} CACHE INTERNAL "" FORCE)
set(LIBHICN_SHARED ${LIBHICN}.shared CACHE INTERNAL "" FORCE)
set(LIBHICN_STATIC ${LIBHICN}.static CACHE INTERNAL "" FORCE)

##############################################################
# Dependencies
##############################################################

if(INTERNAL_ENVIRONMENT)
  include(ImportInternal)
  ImportInternal()
  set(INTERNAL_ENVIRONMENT_FOUND True CACHE STRING "Internal dependency found")
endif()

##############################################################
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)


add_subdirectory(includes)
add_subdirectory(src)
