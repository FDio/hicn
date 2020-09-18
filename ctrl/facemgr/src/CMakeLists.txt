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

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

set(COMPILER_DEFINITIONS
  "-DWITH_POLICY"
)

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

set(INCLUDE_DIRS
    ./
    ../includes/
    ${HICN_INCLUDE_DIRS}
    ${LIBHICNCTRL_INCLUDE_DIRS}
    ${CONFIG_INCLUDE_DIR}
    ${LIBEVENT_INCLUDE_DIR}
)

set(LIBRARIES
    m
    ${HICN_LIBRARIES}
    ${LIBHICNCTRL_LIBRARIES}
    ${CONFIG_LIBRARY}
    ${LIBEVENT_LIBRARY}
)


add_subdirectory(interfaces)

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

if(WITH_EXAMPLE_DUMMY)
    set(COMPILER_DEFINITIONS
        ${COMPILER_DEFINITIONS}
        "-DWITH_EXAMPLE_DUMMY"
    )
endif()

if(WITH_EXAMPLE_UPDOWN)
    set(COMPILER_DEFINITIONS
        ${COMPILER_DEFINITIONS}
        "-DWITH_EXAMPLE_UPDOWN"
    )
endif()

if (DISABLE_SHARED_LIBRARIES)
    build_library(${LIBFACEMGR}
        STATIC
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        DEPENDS ${DEPENDENCIES}
        LINK_LIBRARIES ${LIBRARIES}
        COMPONENT ${FACEMGR}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
else ()
    build_library(${LIBFACEMGR}
        SHARED STATIC NO_DEV
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        DEPENDS ${DEPENDENCIES}
        LINK_LIBRARIES ${LIBRARIES}
        COMPONENT ${FACEMGR}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()

if(NOT DISABLE_EXECUTABLES)
    list(APPEND DAEMON_SRC
      main.c
    )

    build_executable(${FACEMGR}
      SOURCES ${DAEMON_SRC}
      LINK_LIBRARIES ${LIBFACEMGR}.static ${LIBRARIES}
      DEPENDS ${LIBFACEMGR}.static
      COMPONENT ${FACEMGR}
      INCLUDE_DIRS ${INCLUDE_DIRS}
      DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()
