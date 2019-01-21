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

cmake_minimum_required (VERSION 3.5 FATAL_ERROR)
project(Hicn C)
include(CTest)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, default to Release")
	set(CMAKE_BUILD_TYPE "Release")
endif()

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
	set(LIBHICN hicn)
endif()

set(CMAKE_VERSION_MAJOR 0)
set(CMAKE_VERSION_MINOR 1)
set(CMAKE_VERSION_PATCH 1)

option(CMAKE_BUILD_TEST "Build unit tests" OFF)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, default to Release")
	set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_C_FLAGS -Wall)

if (ANDROID_API)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ANDROID_C_FLAGS} -std=c99")
endif ()

add_subdirectory (src)

######################
# Packages section
######################

set(lib${LIBHICN}_DESCRIPTION 
"libhicn provides a support library coded in C \
designed to help developers embed Hybrid ICN (hICN) \
functionalities in their applications (eg. forwarder, \
socket API, etc"
	CACHE STRING "Description for deb/rpm package."
)

set(lib${LIBHICN}-dev_DESCRIPTION ${${LIBHICN}_DESCRIPTION})
set(lib${LIBHICN}-devel_DESCRIPTION ${${LIBHICN}_DESCRIPTION})

set(lib${LIBHICN}-dev_DEB_DEPENDENCIES
	"libhicn (>= 1.0)"
)

set(lib${LIBHICN}-devel_DEB_DEPENDENCIES
	"libhicn >= 1.0"
)
