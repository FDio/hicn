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
    face.c
    route.c
)

if(BUILD_HICNPLUGIN)
    set(SOURCE_FILES
        ${SOURCE_FILES}
        hicn_plugin_api.c
    )
else ()
    set(SOURCE_FILES
        ${SOURCE_FILES}
        api.c
    )
endif()

set(LIBRARIES
    m
    ${HICN_LIBRARIES}
)

set(INCLUDE_DIRS
    ./
    ../includes/
    ${HICN_INCLUDE_DIRS}
)

# Android requires static libraries
if (DISABLE_SHARED_LIBRARIES)
    set(LIBRARIES ${LIBRARIES} ${LIBHICN_STATIC})
    set(LINK_TYPE STATIC)
else ()
    set(LINK_TYPE SHARED STATIC)
endif ()

build_library(${LIBHICNCTRL}
    ${LINK_TYPE}
    SOURCES ${SOURCE_FILES}
    INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
    LINK_LIBRARIES ${LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${LIBHICNCTRL_COMPONENT}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    INSTALL_ROOT_DIR hicn
    DEFINITIONS ${COMPILER_DEFINITIONS}
)

if (NOT DISABLE_EXECUTABLES)
    set(LIBRARIES ${LIBRARIES} ${LIBHICN_SHARED} ${LIBHICNCTRL_SHARED})

    list(APPEND DAEMON_SRC
      cli.c
    )

    build_executable(${HICNCTRL}
      SOURCES ${DAEMON_SRC}
      LINK_LIBRARIES ${LIBRARIES}
      DEPENDS ${LIBHICNCTRL_SHARED}
      COMPONENT ${LIBHICNCTRL_COMPONENT}
      INCLUDE_DIRS ${INCLUDE_DIRS}
      DEFINITIONS ${COMPILER_DEFINITIONS}
      LINK_FLAGS ${LINK_FLAGS}
    )
endif ()
