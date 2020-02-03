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

project(libhicnctrl)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "${PROJECT_NAME}: No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

include(BuildMacros)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_MACOSX_RPATH ON)


set(LIBHICNCTRL hicnctrl)

if (BUILD_HICNPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(LIBHICNCTRL ${LIBHICNCTRL}-memif)
  set(LINK_FLAGS "-Wl,-unresolved-symbols=ignore-in-shared-libs")
  list(APPEND HICN_LIBRARIES ${HICNPLUGIN_LIBRARIES})
  list(APPEND HICN_LIBRARIES ${SAFE_VAPI_LIBRARIES})
endif()

set(LIBHICNCTRL ${LIBHICNCTRL} CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_SHARED ${LIBHICNCTRL}.shared CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_STATIC ${LIBHICNCTRL}.static CACHE INTERNAL "" FORCE)
set(HICNCTRL hicnctrl CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/includes CACHE INTERNAL "" FORCE)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  if (BUILD_HICNPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    find_package_wrapper(HicnPlugin REQUIRED)
  endif()

  find_package_wrapper(Libhicn REQUIRED)
  list(APPEND HICN_LIBRARIES ${LIBHICN_SHARED})

  set(HICN_INCLUDE_DIRS
      ${HICN_INCLUDE_DIRS}
      ${HICNPLUGIN_INCLUDE_DIRS}
      ${SAFE_VAPI_INCLUDE_DIRS})

else()
  if (DISABLE_SHARED_LIBRARIES)
    set(HICN_LIBRARIES ${LIBHICN_STATIC} log)
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
    )
  elseif (BUILD_HICNPLUGIN AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(
      HICN_INCLUDE_DIRS
      ${HICN_INCLUDE_DIRS}
      ${HICNPLUGIN_INCLUDE_DIRS}
      ${SAFE_VAPI_INCLUDE_DIRS}
    )

    list(APPEND DEPENDENCIES
        hicn_plugin
        ${SAFE_VAPI_SHARED}
    )
  else ()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
    )
  endif ()

endif()

set(LIBHICNCTRL_COMPONENT lib${LIBHICNCTRL})

add_subdirectory(includes)
add_subdirectory(src)

include(Packaging)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(Packager)
    make_packages()
endif()
