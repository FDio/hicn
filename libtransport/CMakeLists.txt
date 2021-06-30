# Copyright (c) 2017-2021 Cisco and/or its affiliates.
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

# CMake 3.11 required to use FetchContent
cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

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

set(TRANSPORT_ROOT_PATH "src")

set(LIBTRANSPORT hicntransport)
set(LIBTRANSPORT_COMPONENT libhicntransport)

if ((BUILD_HICNPLUGIN OR BUILD_MEMIF_CONNECTOR) AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(__vpp__ 1)
endif ()

set(LIBTRANSPORT ${LIBTRANSPORT} CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_SHARED ${LIBTRANSPORT}.shared CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_STATIC ${LIBTRANSPORT}.static CACHE INTERNAL "" FORCE)
set(LIBTRANSPORT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src CACHE INTERNAL "" FORCE)

include(WindowsMacros)
include(IosMacros)

find_package_wrapper(Asio REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Libconfig++ REQUIRED)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package_wrapper(Libhicn REQUIRED)
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

include(Packaging)

add_subdirectory(third-party)

set(LIBRARIES
  PRIVATE ${HICN_LIBRARIES}
  PRIVATE ${CMAKE_THREAD_LIBS_INIT}
  PRIVATE ${CMAKE_DL_LIBS}
  PRIVATE ${OPENSSL_LIBRARIES}
  PRIVATE ${LIBCONFIG_CPP_LIBRARIES}
  PRIVATE ${THIRD_PARTY_LIBRARIES}
)

# Include dirs -- Order does matter!
list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
  ${HICN_INCLUDE_DIRS}
  ${HICNPLUGIN_INCLUDE_DIRS}
  ${CMAKE_THREADS_INCLUDE_DIRS}
  ${ASIO_INCLUDE_DIRS}
  ${WINDOWS_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
  ${CONFIG_INCLUDE_DIRS}
  ${THIRD_PARTY_INCLUDE_DIRS}
)

list(APPEND DEPENDENCIES
  ${THIRD_PARTY_DEPENDENCIES}
)

add_subdirectory(includes/hicn/transport)
add_subdirectory(${TRANSPORT_ROOT_PATH})
