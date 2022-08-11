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
# Compiler preferences
##############################################################
set(CMAKE_C_COMPILER_NAMES
  clang-13
  clang-12
  clang-11
  clang-10
  clang-9
  gcc-10
  gcc-9
  cc
)

set(CMAKE_CXX_COMPILER_NAMES
  clang++-13
  clang++-12
  clang++-11
  clang++-10
  clang++-9
  g++-10
  g++-9
  c++
)

##############################################################
# Project and cmake version
##############################################################
cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(hicn-fdio)

##############################################################
# Fetch submodules if needed
##############################################################
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
  # Update submodules as needed
  option(GIT_SUBMODULE "Check submodules during build" ON)
  if(GIT_SUBMODULE)
    message(STATUS "Submodule update")
    execute_process(
      COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      RESULT_VARIABLE GIT_SUBMOD_RESULT
    )

    if(NOT GIT_SUBMOD_RESULT EQUAL "0")
      message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
    endif()
  endif()
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/cmake/Modules")
    message(
      FATAL_ERROR
      "The submodules were not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again."
    )
endif()

##############################################################
# CMake Modules
##############################################################
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")
if(EXISTS "${PROJECT_SOURCE_DIR}/internal/cmake/Modules")
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/internal/cmake/Modules")
  set(INTERNAL_ENVIRONMENT True)
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/versions.cmake")
list(GET VPP_DEFAULT_VERSION 0 VPP_DEFAULT_VERSION)
set(PREFIX_VERSION "${VPP_DEFAULT_VERSION}")
string(REPLACE "-" ";" PREFIX_VERSION ${PREFIX_VERSION})
list (GET PREFIX_VERSION 0 PREFIX_VERSION)

include(CommonSetup)

##############################################################
# Enabled components
##############################################################
option(BUILD_LIBHICN "Build the hicn core library" ON)
option(BUILD_HICNLIGHT "Build the hicn light forwarder" ON)
option(BUILD_LIBTRANSPORT "Build the hicn transport library" ON)
option(BUILD_APPS "Build the hicn apps" ON)
if (NOT WIN32)
  option(BUILD_CTRL "Build the hicn control tools" ON)
  option(DISABLE_SHARED_LIBRARIES "Disable shared libraries" OFF)
else ()
  option(BUILD_CTRL "Build the hicn control tools" OFF)
  option(DISABLE_SHARED_LIBRARIES "Disable shared libraries" ON)
endif ()
option(BUILD_HICNPLUGIN "Build the hicn vpp plugin" OFF)
option(BUILD_EXTRAS "Build external projects" OFF)
option(BUILD_TELEMETRY "Build telemetry projects" OFF)
option(BUILD_TESTS "Build unit tests" OFF)
option(DISABLE_EXECUTABLES "Disable executables" OFF)


##############################################################
# Basic sanity checks
##############################################################
if (BUILD_APPS AND NOT BUILD_LIBTRANSPORT)
  message(STATUS "Libhicntransport required. Enabled by default.")
  set (BUILD_LIBTRANSPORT ON)
endif()

if ((BUILD_HICNLIGHT OR
     BUILD_LIBTRANSPORT OR
     BUILD_APPS OR
     BUILD_CTRL OR
     BUILD_HICNPLUGIN OR
     BUILD_SYSREPOPLUGIN)
     AND NOT BUILD_LIBHICN)
  message(STATUS "Libhicn required. Enabled by default.")
  set(BUILD_LIBHICN ON)
endif()

list(APPEND dir_options
  BUILD_LIBHICN
  BUILD_HICNPLUGIN
  BUILD_CTRL
  BUILD_HICNLIGHT
  BUILD_LIBTRANSPORT
  BUILD_APPS
  BUILD_SYSREPOPLUGIN
  BUILD_EXTRAS
  BUILD_TELEMETRY
)

set(BUILD_LIBHICN_DIR lib)
set(BUILD_HICNLIGHT_DIR hicn-light)
set(BUILD_LIBTRANSPORT_DIR libtransport)
set(BUILD_APPS_DIR apps)
set(BUILD_CTRL_DIR ctrl)
set(BUILD_HICNPLUGIN_DIR hicn-plugin)
set(BUILD_EXTRAS_DIR extras/)
set(BUILD_TELEMETRY_DIR telemetry)


##############################################################
# Add enabled components to the build
##############################################################
foreach (opt ${dir_options})
  if (${opt})
    list(APPEND subdirs
      ${${opt}_DIR}
    )
  endif()
endforeach()


##############################################################
# Build gtest if tests are enabled
##############################################################
if (BUILD_TESTS)
  message(STATUS "Tests enabled.")
  include (GTestImport)

  if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
    include (GoogleTest)
  else()
    include (CTest)
  endif()
endif()

message(STATUS "Building the following subprojects: ${subdirs}")

foreach(dir ${subdirs})
  pr_title("Subproject" "${dir}")
  add_subdirectory(${dir})
endforeach()

add_subdirectory(docs/doxygen)

make_packages()
