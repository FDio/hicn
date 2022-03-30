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
# CMake 3.11 required to use FetchContent
cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(libtransport)


##############################################################
# Cmake modules
##############################################################
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules
)
include("${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake")


##############################################################
# C/CXX Standard
##############################################################
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)


##############################################################
# Libs and Bins names
##############################################################
set(LIBTRANSPORT hicntransport)
set(LIBTRANSPORT_COMPONENT lib${LIBTRANSPORT})

if ((BUILD_HICNPLUGIN OR BUILD_MEMIF_CONNECTOR) AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(__vpp__ 1)
endif ()

set(LIBTRANSPORT ${LIBTRANSPORT} CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_SHARED ${LIBTRANSPORT}.shared CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_STATIC ${LIBTRANSPORT}.static CACHE INTERNAL "" FORCE)


##############################################################
# Dependencies and third party libs
##############################################################
find_package(Asio ${ASIO_DEFAULT_VERSION} REQUIRED)
find_package(OpenSSL ${OPENSSL_DEFAULT_VERSION} EXACT REQUIRED)
find_package(Threads REQUIRED)
find_package(Libconfig++ ${LIBCONFIG_DEFAULT_VERSION} REQUIRED)
add_subdirectory(third-party)


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
  if (DISABLE_SHARED_LIBRARIES)
    if (WIN32)
      set(HICN_LIBRARIES ${LIBHICN_STATIC})
    else ()
      set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    endif ()
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
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)


##############################################################
# Subdirectories
##############################################################
add_subdirectory(includes/hicn/transport)
add_subdirectory(src)
