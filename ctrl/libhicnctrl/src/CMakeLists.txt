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

list(APPEND COMPILER_DEFINITIONS
  "-DWITH_POLICY"
)

set(HEADER_FILES
    api.h
    commands.h
    face.h
)

set(UTIL_HEADER_FILES
    face.h
)

set(SOURCE_FILES
    api.c
    face.c
    route.c
)

set(LIBRARIES
    m
    ${HICN_LIBRARIES}
)

set(INCLUDE_DIRS
    ./
    ../includes/
    ${HICN_INCLUDE_DIRS}
)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    set(HICN_LIBRARIES ${LIBHICN_STATIC})
    build_library(${LIBHICNCTRL}
        STATIC
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        LINK_LIBRARIES ${LIBRARIES}
        DEPENDS ${LIBHICN_STATIC}
        COMPONENT ${LIBHICNCTRL_COMPONENT}
        DEPENDS ${LIBHICN_STATIC}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
else ()
    build_library(${LIBHICNCTRL}
        SHARED STATIC
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        LINK_LIBRARIES ${LIBRARIES}
        DEPENDS ${LIBHICN_SHARED}
        COMPONENT ${LIBHICNCTRL_COMPONENT}
        DEPENDS ${LIBHICN_SHARED}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()

if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Android" AND NOT COMPILE_FOR_IOS)
    list(APPEND DAEMON_SRC
      cli.c
    )
    build_executable(${HICNCTRL}
      SOURCES ${DAEMON_SRC}
      LINK_LIBRARIES ${LIBHICNCTRL_SHARED} ${LIBHICN_SHARED}
      DEPENDS ${LIBHICNCTRL_SHARED} ${LIBHICN_SHARED}
      COMPONENT ${LIBHICNCTRL_COMPONENT}
      INCLUDE_DIRS ${INCLUDE_DIRS}
      DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()
