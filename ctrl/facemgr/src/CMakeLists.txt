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

if(UNIX AND NOT APPLE)
  set(LINUX TRUE)
endif()


##############################################################
# Sources
##############################################################
set(HEADER_FILES
  common.h
  error.h
  facelet_array.h
  interface.h
  loop.h
)

set(SOURCE_FILES
  api.c
  cfg.c
  cfg_file.c
  error.c
  facelet.c
  facelet_array.c
  interface.c
)

if(APPLE)
  set(SOURCE_FILES
    ${SOURCE_FILES}
    loop_dispatcher.c
  )
endif()

if (LINUX)
  set(SOURCE_FILES
    ${SOURCE_FILES}
    loop_libevent.c
  )
endif()

add_subdirectory(interfaces)


##############################################################
# Include directories
##############################################################
set(INCLUDE_DIRS
  PRIVATE ./
  PRIVATE ${CONFIG_INCLUDE_DIR}
  PRIVATE ${LIBEVENT_INCLUDE_DIR}
  PUBLIC
    $<BUILD_INTERFACE:${LIBFACEMGR_INCLUDE_DIRS}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)


##############################################################
# Libraries to link
##############################################################
set(LIBRARIES
  PUBLIC ${HICN_LIBRARIES}
  PUBLIC ${LIBHICNCTRL_LIBRARIES}
  PRIVATE m
  PRIVATE ${LIBCONFIG_LIBRARIES}
  PRIVATE ${LIBEVENT_LIBRARY}
)

if(WITH_THREAD)
  set(LIBRARIES
    ${LIBRARIES}
    "pthread"
    "event_pthreads"
  )
  set(COMPILER_DEFINITIONS
    ${COMPILER_DEFINITIONS}
    "-DWITH_THREAD"
  )
endif()


##############################################################
# Compiler definitions
##############################################################

if(WITH_THREAD)
  list(APPEND COMPILER_DEFINITIONS
    "-DWITH_THREAD"
  )
endif()

if(WITH_EXAMPLE_DUMMY)
  list(APPEND COMPILER_DEFINITIONS
    "-DWITH_EXAMPLE_DUMMY"
  )
endif()

if(WITH_EXAMPLE_UPDOWN)
  list(APPEND COMPILER_DEFINITIONS
    "-DWITH_EXAMPLE_UPDOWN"
  )
endif()


##############################################################
# Compiler options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)


##############################################################
# Build type
##############################################################
if (DISABLE_SHARED_LIBRARIES)
    set(LINK_TYPE STATIC)
else ()
    set(LINK_TYPE SHARED STATIC)
endif ()


##############################################################
# Build libfacemgr
##############################################################
build_library(${LIBFACEMGR}
  ${LINK_TYPE}
  SOURCES ${SOURCE_FILES}
  INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
  DEPENDS ${DEPENDENCIES}
  LINK_LIBRARIES ${LIBRARIES}
  COMPONENT ${FACEMGR}
  INCLUDE_DIRS PRIVATE ${INCLUDE_DIRS}
  DEFINITIONS PRIVATE ${COMPILER_DEFINITIONS}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)


##############################################################
# Build executable
##############################################################
if(NOT DISABLE_EXECUTABLES)
  list(APPEND DAEMON_SRC
    main.c
  )

  build_executable(${FACEMGR}
    SOURCES ${DAEMON_SRC}
    LINK_LIBRARIES PRIVATE ${LIBFACEMGR}.static
    DEPENDS ${LIBFACEMGR}.static
    COMPONENT ${FACEMGR}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )
endif ()
