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
cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0048 NEW)
project(packethicn VERSION 0.0.1 DESCRIPTION "hICN protocol plugin" LANGUAGES C)


##############################################################
# Cmake modules
##############################################################
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules
)


##############################################################
# Naming
##############################################################
set(PACKETHICN packethicn)


##############################################################
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../../versions.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)


##############################################################
# Dependencies and third party libs
##############################################################
if(APPLE)
  find_package(Wireshark CONFIG REQUIRED
    PATHS /usr/local/opt/wireshark/lib/wireshark/cmake/ /usr/local/Cellar/wireshark/*/lib/wireshark/cmake
  )
else()
  find_package(Wireshark CONFIG REQUIRED)
endif()

MATH(EXPR Wireshark_PATCH_NEXT_VERSION "${Wireshark_PATCH_VERSION}+1")
set(Wireshark_NEXT_VERSION ${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}.${Wireshark_PATCH_NEXT_VERSION})


##############################################################
# Check if building as subproject or as root project
##############################################################
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  include(CommonSetup)
  find_package(Libhicn ${CURRENT_VERSION} REQUIRED NO_MODULE)

  if (DISABLE_SHARED_LIBRARIES)
    set(LIBTYPE static)
  else()
    set(LIBTYPE shared)
  endif()

  list(APPEND HICN_LIBRARIES hicn::hicn.${LIBTYPE})
else()
  if(DISABLE_SHARED_LIBRARIES)
    if(WIN32)
      set(HICN_LIBRARIES ${LIBHICN_STATIC})
    else()
      set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    endif()
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
    )
  else()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
    )
  endif()
endif()


##############################################################
# Check if wiresharks supports plugins
##############################################################
if(NOT Wireshark_PLUGINS_ENABLED)
  message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()


##############################################################
# Compilaer flags
##############################################################
set(CMAKE_C_VISIBILITY_PRESET hidden)


##############################################################
# Compiler definitions
##############################################################
set(COMPILER_DEFINITIONS -DVERSION=\"${PROJECT_VERSION}\")


##############################################################
# Sources
##############################################################
set(SOURCE_FILES
  packet-hicn.c
)


##############################################################
# Include dirs
##############################################################
list(APPEND PACKETHICN_INCLUDE_DIRS
  ${HICN_INCLUDE_DIRS}
)


##############################################################
# Libraries
##############################################################
list(APPEND LIBRARIES
  ${HICN_LIBRARIES}
  epan
)


##############################################################
# Build library
##############################################################
build_library(${PACKETHICN}
  SOURCES ${SOURCE_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${PACKETHICN}
  INCLUDE_DIRS ${PACKETHICN_INCLUDE_DIRS}
  INSTALL_FULL_PATH_DIR ${Wireshark_PLUGIN_INSTALL_DIR}/epan
  DEFINITIONS ${COMPILER_DEFINITIONS}
)


##############################################################
# Make package if needed
##############################################################
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    make_packages()
endif()