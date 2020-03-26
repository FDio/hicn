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

project(hicn-light)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(ENABLE_PUNTING "Enable punting on linux systems" ON)

include( CTest )
include( detectCacheSize )

if(NOT WIN32)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
else ()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4996")
endif ()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
  message("############ Detected cross compile for $ENV{CMAKE_SYSTEM_NAME}")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ANDROID_C_FLAGS}")
endif()

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DLIBRTA_DISABLE_VALIDATION -DPARCLibrary_DISABLE_VALIDATION")

include(IosMacros)
include(WindowsMacros)

find_package_wrapper(Libparc REQUIRED)

set(HICN_LIGHT hicn-light CACHE INTERNAL "" FORCE)
set(HICN_LIGHT_CONTROL ${HICN_LIGHT}-control CACHE INTERNAL "" FORCE)
set(HICN_LIGHT_DAEMON ${HICN_LIGHT}-daemon CACHE INTERNAL "" FORCE)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package_wrapper(Libhicn REQUIRED)
else()
  if (DISABLE_SHARED_LIBRARIES)
    set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
    )
  else ()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
    )
  endif ()
endif()

include(Packaging)

find_package(Threads REQUIRED)

set(LIBHICN_LIGHT hicn-light)
set(LIBHICN_LIGHT_STATIC ${LIBHICN_LIGHT}.static)

set(HICN_LIGHT_LINK_LIBRARIES
  ${LIBHICN_LIGHT_STATIC}
  ${HICN_LIBRARIES}
  ${LIBPARC_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${WINDOWS_LIBRARIES}
)


# Include dirs -- Order does matter!
list(APPEND HICN_LIGHT_INCLUDE_DIRS
  ${HICN_INCLUDE_DIRS}
  ${LIBPARC_INCLUDE_DIRS}
  ${WINDOWS_INCLUDE_DIRS}
)

if (UNIX)
  list(APPEND HICN_LIGHT_LINK_LIBRARIES
    m
  )
endif()

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
  set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")
	message(STATUS "Set \"-undefined dynamic_lookup\" for shared libraries")
endif()

add_subdirectory(src/hicn)

# Install service file in linux systems
include(ServiceScript)
install_service_script(
  ${CMAKE_CURRENT_SOURCE_DIR}/config/hicn-light.service
  COMPONENT ${HICN_LIGHT}
)
