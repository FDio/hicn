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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(libtransport)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

include(DefaultConfiguration)
include(BuildMacros)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE "Release")
endif ()

#########################################
# LOG LEVELS AVAILABLE
# VERBOSE
# DEBUG
# INFO
# WARN
# ERROR
# FATAL
# NONE
#
# Default: INFO
set(TRANSPORT_LOG_LEVEL "INFO" CACHE STRING "Set log level")

set(TRANSPORT_ROOT_PATH "src/hicn/transport")

set(TRANSPORT_CORE ${TRANSPORT_ROOT_PATH}/core)
set(TRANSPORT_TRANSPORT ${TRANSPORT_ROOT_PATH}/transport)
set(TRANSPORT_ERRORS ${TRANSPORT_ROOT_PATH}/errors)
set(TRANSPORT_UTILS ${TRANSPORT_ROOT_PATH}/utils)
set(TRANSPORT_HTTP ${TRANSPORT_ROOT_PATH}/http)
set(TRANSPORT_PORTABILITY ${TRANSPORT_ROOT_PATH}/portability)
set(TRANSPORT_INTERFACES ${TRANSPORT_ROOT_PATH}/interfaces)

# Install includes
set(INSTALL_INCLUDE_DIR include/hicn/transport)

set(LIBTRANSPORT hicntransport)
if ((BUILD_HICNPLUGIN OR BUILD_MEMIF_CONNECTOR) AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(__vpp__ 1)
  set(LIBTRANSPORT ${LIBTRANSPORT}-memif)
  find_package(Vpp REQUIRED)

  list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
    ${VPP_INCLUDE_DIRS}
  )
endif ()

set(LIBTRANSPORT ${LIBTRANSPORT} CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_SHARED ${LIBTRANSPORT}.shared CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_STATIC ${LIBTRANSPORT}.static CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src CACHE INTERNAL "" FORCE)

include(WindowsMacros)
include(IosMacros)
find_package_wrapper(Libparc REQUIRED)
find_package_wrapper(Asio REQUIRED)
find_package(OpenSSL REQUIRED)

if (__vpp__)
  find_package(Libmemif REQUIRED)
endif()

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  if (__vpp__)
    find_package(HicnPlugin REQUIRED)
    find_package(SafeVapi REQUIRED)

    list(APPEND LIBRARIES
      ${LIBMEMIF_LIBRARIES}
      ${SAFE_VAPI_LIBRARIES}
    )
  endif()

  find_package_wrapper(Libhicn REQUIRED)
else()
  if (DISABLE_SHARED_LIBRARIES)
    set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
    )
  else()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
    )

    if (__vpp__)
      list(APPEND DEPENDENCIES
        hicn_plugin
        ${SAFE_VAPI_SHARED}
      )

      list(APPEND LIBRARIES
        ${LIBMEMIF_LIBRARIES}
        ${SAFE_VAPI_LIBRARIES}
      )
    endif()
  endif()
endif()

list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
  ${LIBMEMIF_INCLUDE_DIRS}
  ${SAFE_VAPI_INCLUDE_DIRS}
)

include(Packaging)

find_package(Threads REQUIRED)

if (${COMPILE_TESTS})
  include(TestMacros)
  find_package(GTest REQUIRED)
  list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
    ${GTEST_INCLUDE_DIRS}
  )
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
  find_package(OpenSSL REQUIRED)
endif ()

list(APPEND LIBRARIES
  ${LIBPARC_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${HICN_LIBRARIES}
  ${VPP_LIBRARIES}
  ${ANDROID_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${WINDOWS_LIBRARIES}
  ${LIBHICNCTRL_LIBRARIES}
)

# Include dirs -- Order does matter!
list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
  ${HICN_INCLUDE_DIRS}
  ${HICNPLUGIN_INCLUDE_DIRS}
  ${LIBPARC_INCLUDE_DIRS}
  ${CMAKE_THREADS_INCLUDE_DIRS}
  ${ASIO_INCLUDE_DIRS}
  ${WINDOWS_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
)

add_subdirectory(${TRANSPORT_ROOT_PATH})
