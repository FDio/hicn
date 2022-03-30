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
# Libs and Bins names
##############################################################
set(SAFE_VAPI safevapi CACHE INTERNAL "" FORCE)
set(SAFE_VAPI_SHARED ${SAFE_VAPI}.shared CACHE INTERNAL "" FORCE)
set(SAFE_VAPI_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/includes CACHE INTERNAL "" FORCE)
set(SAFE_VAPI_LIBRARIES ${SAFE_VAPI_SHARED} CACHE INTERNAL "" FORCE)


##############################################################
# Dependencies and third party libs
##############################################################
find_package(Vpp ${VPP_DEFAULT_VERSION} EXACT REQUIRED)


##############################################################
# Check if building as subproject or as root project
##############################################################
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  include(CommonSetup)
  find_package(HicnPlugin ${CURRENT_VERSION} EXACT REQUIRED)
else()
  list(APPEND DEPENDENCIES
    ${HICNPLUGIN}
  )
endif()


##############################################################
# Sources
##############################################################
list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/includes/vapi/vapi_safe.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/vapi_safe.c
)


##############################################################
# Compiler Options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
  ${MARCH_COMPILER_OPTIONS}
)


##############################################################
# Libraries to link
##############################################################
set (LIBRARIES
  ${VPP_LIBRARY_VAPICLIENT}
)


##############################################################
# Include directories
##############################################################
list (APPEND INCLUDE_DIRS
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
    $<BUILD_INTERFACE:${HICNPLUGIN_INCLUDE_DIRS}>
    $<BUILD_INTERFACE:${VPP_INCLUDE_DIR}>
    $<BUILD_INTERFACE:${SAFE_VAPI_INCLUDE_DIRS}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)


##############################################################
# Build library
##############################################################
build_library(${SAFE_VAPI}
  SHARED
  SOURCES ${SOURCE_FILES} ${HEADER_FILES}
  INSTALL_HEADERS ${HEADER_FILES}
  LINK_LIBRARIES PRIVATE ${LIBRARIES}
  COMPONENT ${HICN_PLUGIN}
  INCLUDE_DIRS ${INCLUDE_DIRS}
  HEADER_ROOT_DIR ""
  DEFINITIONS PUBLIC ${COMPILER_DEFINITIONS}
  DEPENDS ${HICNPLUGIN}.shared
  VERSION ${CURRENT_VERSION}
  EXPORT_NAME "libsafevapi"
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)


##############################################################
# Create cmake configuration
##############################################################
create_cmake_config (
  "libsafevapi"
  INCLUDE_DIRS ${SAFE_VAPI_INCLUDE_DIRS}
  VERSION ${CURRENT_VERSION}
  COMPONENT ${HICN_PLUGIN}
  NAMESPACE hicn
)
