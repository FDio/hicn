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

cmake_minimum_required (VERSION 3.10 FATAL_ERROR)
project(libhicn C)
#include(CTest)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
	set(CMAKE_BUILD_TYPE "Release")
endif()

set(LIBHICN hicn CACHE INTERNAL "" FORCE)
set(LIBHICN_SHARED ${LIBHICN}.shared CACHE INTERNAL "" FORCE)
set(LIBHICN_STATIC ${LIBHICN}.static CACHE INTERNAL "" FORCE)
set(HICN_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/includes CACHE INTERNAL "" FORCE)

include (Packaging)

option(CMAKE_BUILD_TEST "Build unit tests" OFF)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
	set(CMAKE_BUILD_TYPE "Release")
endif()

if (NOT WIN32)
  set(CMAKE_C_FLAGS -Wall)
else ()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4996")
endif ()

add_subdirectory(includes)
add_subdirectory (src)

