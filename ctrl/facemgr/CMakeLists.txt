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
project(facemgr)

if (APPLE)
  # >= 3.13 - CMP0079 (only needed on Apple platform for conditionally linking Network.framwork to libfacemgr)
  cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
else()
  cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
endif()


##############################################################
# C Standard
##############################################################
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

##############################################################
# CMAKE Options
##############################################################
option(WITH_THREAD "Run library as thread" OFF)
option(WITH_EXAMPLE_DUMMY "Compile dummy example interface" OFF)
option(WITH_EXAMPLE_UPDOWN "Compile updown example interface" OFF)

if(WITH_THREAD)
  message(STATUS "Building with thread support")
endif()

if(WITH_EXAMPLE_DUMMY)
  message(STATUS "Building with 'dummy' example interface")
endif()

if(WITH_EXAMPLE_UPDOWN)
  message(STATUS "Building with 'updown' example interface")
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3")
endif()


##############################################################
# Cmake modules
##############################################################
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules"
)


##############################################################
# Libs and Bins names
##############################################################
set(FACEMGR facemgr CACHE INTERNAL "" FORCE)
set(LIBFACEMGR facemgr CACHE INTERNAL "" FORCE)


##############################################################
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../../versions.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)


##############################################################
# Dependencies and third party libs
##############################################################
find_package(Libconfig ${LIBCONFIG_DEFAULT_VERSION} REQUIRED)
find_package(LibEvent ${LIBEVENT_DEFAULT_VERSION} REQUIRED)


##############################################################
# Check if building as subproject or as root project
##############################################################
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  include(CommonSetup)

  find_package(Libhicn ${CURRENT_VERSION} REQUIRED NO_MODULE)
  find_package(Libhicnctrl ${CURRENT_VERSION} REQUIRED NO_MODULE)

  if (DISABLE_SHARED_LIBRARIES)
    set(LIBTYPE static)
  else()
    set(LIBTYPE shared)
  endif()

  list(APPEND HICN_LIBRARIES hicn::hicn.${LIBTYPE})
  list(APPEND LIBHICNCTRL_LIBRARIES hicn::hicnctrl.${LIBTYPE})
else()
  if (DISABLE_SHARED_LIBRARIES)
    if (WIN32)
      set(HICN_LIBRARIES ${LIBHICN_STATIC})
    else ()
      set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    endif ()
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


##############################################################
# Subdirectories
##############################################################
add_subdirectory(includes)
add_subdirectory(src)



##############################################################
# Service file
##############################################################
# Install service file in linux systems
include(ServiceScript)
install_service_script(
  ${CMAKE_CURRENT_SOURCE_DIR}/config/facemgr.service
  COMPONENT ${FACEMGR}
)


##############################################################
# Configuration file
##############################################################
set(FACEMGR_CONF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/config/facemgr.conf)
if (${CMAKE_SYSTEM_NAME} MATCHES Darwin OR ${CMAKE_SYSTEM_NAME} MATCHES Linux)
  set(FACEMGR_CONF_FOLDER "${CMAKE_INSTALL_FULL_SYSCONFDIR}/facemgr")
else ()
  set(FACEMGR_CONF_FOLDER "${CMAKE_INSTALL_PREFIX}/etc/hicn")
endif()

install (FILES
  ${FACEMGR_CONF_FILE}
  DESTINATION ${FACEMGR_CONF_FOLDER}
  COMPONENT ${FACEMGR}
)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  make_packages()
endif()
