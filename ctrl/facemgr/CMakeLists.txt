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

if (APPLE)
    # >= 3.13 - CMP0079 (only needed on Apple platform for conditionally linking Network.framwork to libfacemgr)
    cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
else()
    cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
endif()

project(facemgr)

option(WITH_THREAD "Run library as thread" OFF)
option(WITH_EXAMPLE_DUMMY "Compile dummy example interface" OFF)
option(WITH_EXAMPLE_UPDOWN "Compile updown example interface" OFF)

if(WITH_THREAD)
    message("Building with thread support")
endif()

if(WITH_EXAMPLE_DUMMY)
    message("Building with 'dummy' example interface")
endif()

if(WITH_EXAMPLE_UPDOWN)
    message("Building with 'updown' example interface")
endif()

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
message("IN DEBUG MODE")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3")
endif()

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

include(BuildMacros)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)

find_package_wrapper(Config REQUIRED)
find_package_wrapper(LibEvent REQUIRED)

set(FACEMGR facemgr CACHE INTERNAL "" FORCE)
set(LIBFACEMGR facemgr CACHE INTERNAL "" FORCE)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package_wrapper(Libhicn REQUIRED)
  find_package_wrapper(Libhicnctrl REQUIRED)
else()
  if (DISABLE_SHARED_LIBRARIES)
    set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_STATIC})
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
      ${LIBHICNCTRL_STATIC}
    )
  else ()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
      ${LIBHICNCTRL_SHARED}
    )
  endif ()
endif()

add_subdirectory(includes)
add_subdirectory(src)

include(Packaging)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(Packager)
    make_packages()
endif()
