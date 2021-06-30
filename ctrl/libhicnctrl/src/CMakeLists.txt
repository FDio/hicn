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

set(SOURCE_FILES
    face.c
    route.c
    api.c
)

set(HEADER_FILES
    api_private.h
)

set(LIBRARIES
    m
    dl
    ${HICN_LIBRARIES}
)

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../includes/
    ${HICN_INCLUDE_DIRS}
)

# Android requires static libraries
if (DISABLE_SHARED_LIBRARIES)
    set(LIBRARIES ${LIBRARIES} ${LIBHICN_STATIC})
    set(LINK_TYPE STATIC)
else ()
    set(LINK_TYPE SHARED STATIC)
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES Android)
    list(APPEND SOURCE_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/modules/hicn_light_api.c
    )
else()
    add_subdirectory(modules)
endif()

build_library(${LIBHICNCTRL}
    ${LINK_TYPE}
    SOURCES ${SOURCE_FILES} ${HEADER_FILES}
    INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
    LINK_LIBRARIES ${LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${LIBHICNCTRL_COMPONENT}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    HEADER_ROOT_DIR hicn
    DEFINITIONS ${COMPILER_DEFINITIONS}
)

if (NOT DISABLE_EXECUTABLES)
    if (DISABLE_SHARED_LIBRARIES)
        set(LIBRARIES ${LIBRARIES} ${LIBHICNCTRL_STATIC})
        set(DEPENDENCIES ${LIBHICNCTRL_STATIC})
    else ()
        set(LIBRARIES ${LIBRARIES} ${LIBHICN_SHARED} ${LIBHICNCTRL_SHARED})
        set(DEPENDENCIES ${LIBHICNCTRL_SHARED})
    endif ()
    
    list(APPEND DAEMON_SRC
      cli.c
    )

    build_executable(${HICNCTRL}
      SOURCES ${DAEMON_SRC}
      LINK_LIBRARIES ${LIBRARIES}
      DEPENDS ${DEPENDENCIES}
      COMPONENT ${LIBHICNCTRL_COMPONENT}
      INCLUDE_DIRS ${INCLUDE_DIRS}
      DEFINITIONS ${COMPILER_DEFINITIONS}
      LINK_FLAGS ${LINK_FLAGS}
    )
endif ()
