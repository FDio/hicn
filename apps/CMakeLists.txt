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
project(apps)


##############################################################
# C Standard
##############################################################
set(CMAKE_CXX_STANDARD 17)


##############################################################
# Cmake modules
##############################################################
include("${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake")
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules
)


##############################################################
# Libs and Bins names
##############################################################
set(HICN_APPS hicn-apps CACHE INTERNAL "" FORCE)
set(HIGET higet)
set(HTTP_PROXY hicn-http-proxy)
set(LIBHTTP_PROXY hicnhttpproxy)
set(LIBHTTP_PROXY_STATIC ${LIBHTTP_PROXY}.static)


##############################################################
# Dependencies and third party libs
##############################################################
find_package(Threads REQUIRED)
find_package(Libconfig++ ${LIBCONFIG_DEFAULT_VERSION} REQUIRED)


##############################################################
# Check if building as subproject or as root project
##############################################################
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  include(CommonSetup)

  find_package(Libhicn ${CURRENT_VERSION} REQUIRED NO_MODULE)
  find_package(Libhicnctrl ${CURRENT_VERSION} REQUIRED NO_MODULE)
  find_package(Libhicntransport ${CURRENT_VERSION} REQUIRED NO_MODULE)

  if (DISABLE_SHARED_LIBRARIES)
    set(LIBTYPE static)
  else()
    set(LIBTYPE shared)
  endif()

  list(APPEND LIBHICN_LIBRARIES hicn::hicn.${LIBTYPE})
  list(APPEND LIBTRANSPORT_LIBRARIES hicn::hicntransport.${LIBTYPE})
  list(APPEND LIBHICNCTRL_LIBRARIES hicn::hicnctrl.${LIBTYPE})
else()
  if (DISABLE_SHARED_LIBRARIES)
    find_package(OpenSSL ${OPENSSL_DEFAULT_VERSION} REQUIRED)
    set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_STATIC})
    set(LIBHICN_LIBRARIES ${LIBHICN_STATIC})
    set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_STATIC})
  else ()
    set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_SHARED})
    set(LIBHICN_LIBRARIES ${LIBHICN_SHARED})
    set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_SHARED})
  endif ()

  list(APPEND DEPENDENCIES
    ${LIBTRANSPORT_LIBRARIES}
  )
endif()


##############################################################
# Packaging and versioning
##############################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../versions.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/packaging.cmake)


##############################################################
# Subdirectories
##############################################################
add_subdirectory(ping)
add_subdirectory(hiperf)
add_subdirectory(http-proxy)
add_subdirectory(higet)
