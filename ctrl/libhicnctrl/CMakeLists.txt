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
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(libhicnctrl)


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
set(LIBHICNCTRL hicnctrl)
set(LIBHICNCTRL ${LIBHICNCTRL} CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_SHARED ${LIBHICNCTRL}.shared CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_STATIC ${LIBHICNCTRL}.static CACHE INTERNAL "" FORCE)
set(HICNCTRL hicnctrl CACHE INTERNAL "" FORCE)
set(LIBHICNCTRL_COMPONENT lib${LIBHICNCTRL})
set(LIBHICNCTRL_COMPONENT_MODULES ${LIBHICNCTRL_COMPONENT}-modules)


##############################################################
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../../versions.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)


##############################################################
# C Standard
##############################################################
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_MACOSX_RPATH ON)


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
  else ()
    set(HICN_LIBRARIES ${LIBHICN_SHARED})
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
    )
  endif ()
endif()


##############################################################
# Include directories
##############################################################
add_subdirectory(includes)
add_subdirectory(src)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  make_packages()
endif()
