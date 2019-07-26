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
#cache.h
    common.h
    error.h
    event.h
    face.h
    face_cache.h
    face_rules.h
    interface.h
    interface_map.h
    interface_ops_map.h
    util/hash.h
    util/ip_address.h
    util/log.h
    util/map.h
    util/policy.h
    util/set.h
    util/token.h
    util/types.h

)

set(SOURCE_FILES
#   cache.c
    error.c
    event.c
    face.c
    face_cache.c
    face_rules.c
    interface.c
    interface_map.c
    interface_ops_map.c
    facemgr.c
    util/log.c
    util/policy.c
)

message("---->"  ${LIBHICNCTRL_INCLUDE_DIRS})

set(INCLUDE_DIRS
    ./
    ../includes/
    ${CONFIG_INCLUDE_DIR}
    ${LIBEVENT_INCLUDE_DIR}
    ${LIBHICNCTRL_INCLUDE_DIRS}
)

set(LIBRARIES
    ${CONFIG_LIBRARY}
    ${LIBEVENT_LIBRARY}
)

add_subdirectory(interfaces)

if (ANDROID_API)
    build_library(${FACE_MGR}
        STATIC
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        DEPENDS ${DEPENDENCIES}
        COMPONENT ${FACE_MGR}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
else ()
    build_library(${FACE_MGR}
        STATIC NO_DEV
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        DEPENDS ${DEPENDENCIES}
        COMPONENT ${FACE_MGR}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()

if(NOT ANDROID_API AND NOT COMPILE_FOR_IOS)
    list(APPEND DAEMON_SRC
      main.c
    )

    build_executable(${FACE_MGR}
      SOURCES ${DAEMON_SRC}
      LINK_LIBRARIES ${FACE_MGR}.static ${LIBRARIES}
      DEPENDS ${FACE_MGR}.static
      COMPONENT ${FACE_MGR}
      INCLUDE_DIRS ${INCLUDE_DIRS}
      DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()
