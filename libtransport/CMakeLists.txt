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
  message(STATUS "No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE "Release")
endif ()

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

if ((BUILD_HICNPLUGIN OR BUILD_MEMIF_CONNECTOR) AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(__vpp__ 1)
  find_package(Vpp REQUIRED)
  find_package(Libmemif REQUIRED)
  list(APPEND LIBTRANSPORT_INCLUDE_DIRS
    ${VPP_INCLUDE_DIRS}
    ${LIBMEMIF_INCLUDE_DIRS}
  )

  list(APPEND LIBRARIES
    # ${VPP_INCLUDE_DIRS}
    ${LIBMEMIF_LIBRARIES}
  )
endif ()

include(WindowsMacros)
include(IosMacros)
find_package_wrapper(Libparc REQUIRED)
find_package_wrapper(Asio REQUIRED)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package_wrapper(Libhicn REQUIRED)
  if (__vpp__)
    find_package_wrapper(HicnBinaryApi REQUIRED)
  endif()
  set(LIBTRANSPORT hicntransport)
else()
  set(HICN_LIBRARIES ${LIBHICN_SHARED})
  list(APPEND DEPENDENCIES
    ${LIBHICN}
    ${LIBHICN_SHARED}
  )

  if (__vpp__)
    list(APPEND DEPENDENCIES
      hicn_plugin
    )
  endif()
endif()

include(Packaging)

find_package(Threads REQUIRED)

if (${COMPILE_TESTS})
  include(TestMacros)
  find_package(GTest REQUIRED)
  list(APPEND LIBTRANSPORT_INCLUDE_DIRS
    ${GTEST_INCLUDE_DIRS}
  )
endif()

list(APPEND LIBRARIES
  ${LIBPARC_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${HICN_LIBRARIES}
  ${VPP_LIBRARIES}
  ${ANDROID_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${WINDOWS_LIBRARIES}
)

# Include dirs -- Order does matter!
list(APPEND LIBTRANSPORT_INCLUDE_DIRS
  ${HICN_INCLUDE_DIRS}
  ${HICN_BINARY_API_INCLUDE_DIRS}
  ${LIBPARC_INCLUDE_DIRS}
  ${CMAKE_THREADS_INCLUDE_DIRS}
  ${ASIO_INCLUDE_DIRS}
  ${WINDOWS_INCLUDE_DIRS}
)

add_subdirectory(${TRANSPORT_ROOT_PATH})
