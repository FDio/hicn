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
# Source files
##############################################################
set(SOURCE_FILES
  route.c
  api.c
)

set(HEADER_FILES
  api_private.h
)


##############################################################
# Libraries to link
##############################################################
set(LIBRARIES
  m
  dl
  ${HICN_LIBRARIES}
)


##############################################################
# Include directories
##############################################################
set(INCLUDE_DIRS
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC
    $<BUILD_INTERFACE:${Libhicnctrl_INCLUDE_DIRS}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)


##############################################################
# Library type
##############################################################
if (DISABLE_SHARED_LIBRARIES)
  set(LIBRARIES ${LIBRARIES} ${LIBHICN_STATIC})
  set(LINK_TYPE STATIC)
else ()
  set(LINK_TYPE SHARED STATIC)
endif ()


##############################################################
# Do not use modules if Android
##############################################################

if (${CMAKE_SYSTEM_NAME} MATCHES Android OR ${CMAKE_SYSTEM_NAME} MATCHES iOS)
  list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/hicn_light_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/hicn_light_ng_api.c
  )
else()
  add_subdirectory(modules)
endif()


##############################################################
# Compiler options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)


##############################################################
# Build main hicnctrl library
##############################################################
build_library(${LIBHICNCTRL}
  ${LINK_TYPE}
  SOURCES ${SOURCE_FILES} ${HEADER_FILES}
  INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${LIBHICNCTRL_COMPONENT}
  INCLUDE_DIRS ${INCLUDE_DIRS}
  DEFINITIONS PUBLIC ${COMPILER_DEFINITIONS}
  VERSION ${CURRENT_VERSION}
  EXPORT_NAME "${LIBHICNCTRL_COMPONENT}"
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)


##############################################################
# Cmake config files
##############################################################
create_cmake_config (
  ${LIBHICNCTRL_COMPONENT}
  INCLUDE_DIRS ${Libhicnctrl_INCLUDE_DIRS}
  VERSION ${CURRENT_VERSION}
  COMPONENT ${LIBHICNCTRL_COMPONENT}
  NAMESPACE hicn
)


##############################################################
# Build executables
##############################################################
if (NOT DISABLE_EXECUTABLES)
  if (DISABLE_SHARED_LIBRARIES)
    set(LIBRARIES ${LIBRARIES} ${LIBHICNCTRL_STATIC})
    set(DEPENDENCIES ${LIBHICNCTRL_STATIC})
  else ()
    set(LIBRARIES ${LIBRARIES} ${LIBHICN_SHARED} ${LIBHICNCTRL_SHARED})
    set(DEPENDENCIES ${LIBHICNCTRL_SHARED})
  endif ()

  list(APPEND DAEMON_SRC
    hicnctrl.c
  )

  build_executable(${HICNCTRL}
    SOURCES ${DAEMON_SRC}
    LINK_LIBRARIES ${LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${LIBHICNCTRL_COMPONENT}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    LINK_FLAGS ${LINK_FLAGS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )
endif ()
