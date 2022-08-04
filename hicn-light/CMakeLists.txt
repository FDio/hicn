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
project(hicn-light)


##############################################################
# Libs and Bins names
##############################################################
set(LIBHICN_LIGHT hicn-light)
set(LIBHICN_LIGHT_STATIC ${LIBHICN_LIGHT}.static)


##############################################################
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake)


##############################################################
# Cmake modules
##############################################################
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)


##############################################################
# C Standard
##############################################################
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)


##############################################################
# Libs and Bins names
##############################################################
set(HICN_LIGHT hicn-light CACHE INTERNAL "" FORCE)
set(HICN_LIGHT_CONTROL ${HICN_LIGHT}-control CACHE INTERNAL "" FORCE)
set(HICN_LIGHT_SHELL ${HICN_LIGHT}-shell CACHE INTERNAL "" FORCE)
set(HICN_LIGHT_DAEMON ${HICN_LIGHT}-daemon CACHE INTERNAL "" FORCE)


##############################################################
# Dependencies and third party libs
##############################################################
find_package(LibEvent ${LIBEVENT_DEFAULT_VERSION} REQUIRED)
find_package(Threads REQUIRED)


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
      set(HICN_LIBRARIES ${LIBHICN_STATIC} ${LIBHICNCTRL_STATIC})
    else ()
      set(HICN_LIBRARIES ${LIBHICN_STATIC} ${LIBHICNCTRL_STATIC} log)
    endif ()
    list(APPEND DEPENDENCIES
      ${LIBHICN_STATIC}
      ${LIBHICNCTRL_STATIC}
    )
  else ()
    set(HICN_LIBRARIES
      ${LIBHICN_SHARED}
      ${LIBHICNCTRL_SHARED}
    )
    list(APPEND DEPENDENCIES
      ${LIBHICN_SHARED}
      ${LIBHICNCTRL_SHARED}
    )
  endif ()
endif()


##############################################################
# Subdirectories
##############################################################
add_subdirectory(src/hicn)


##############################################################
# Install service file in linux systems
##############################################################
include(ServiceScript)
install_service_script(
  ${CMAKE_CURRENT_SOURCE_DIR}/config/hicn-light.service
  COMPONENT ${HICN_LIGHT}
)
