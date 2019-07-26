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

include(BuildMacros)

list(APPEND COMPILER_DEFINITIONS
  "-DWITH_POLICY"
#  "-DWITH_UPDATE"
)

set(HEADER_FILES
    api.h
    commands.h
    face.h
)

set(UTIL_HEADER_FILES
    face.h
    util/ip_address.h
    util/log.h
    util/policy.h
    util/token.h
    util/types.h
)

set(SOURCE_FILES
    api.c
    util/policy.c
    util/log.c
)

set(LIBRARIES
    m
)

set(INCLUDE_DIRS
    ./
    ../includes/
)

set(TO_INSTALL_HEADER_FILES
    ../includes/ctrl.h # workaround
    ../includes/hicn/ctrl/api.h
    ../includes/hicn/ctrl/commands.h
    ../includes/hicn/ctrl/face.h
)


if (ANDROID_API)
    build_library(${HICNCTRL}
        STATIC
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        LINK_LIBRARIES ${LIBRARIES}
        COMPONENT ${HICNCTRL}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
else ()
    build_library(${HICNCTRL}
        SHARED
        SOURCES ${SOURCE_FILES}
        INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
        LINK_LIBRARIES ${LIBRARIES}
        COMPONENT ${HICNCTRL}
        INCLUDE_DIRS ${INCLUDE_DIRS}
        INSTALL_ROOT_DIR hicn
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()

if(NOT ANDROID_API AND NOT COMPILE_FOR_IOS)
    list(APPEND DAEMON_SRC
      cli.c
    )
    build_executable(${HICNCTRL}
      SOURCES ${DAEMON_SRC}
      LINK_LIBRARIES ${HICNCTRL}.shared
      DEPENDS ${HICNCTRL}.shared
      COMPONENT ${HICNCTRL}
      INCLUDE_DIRS ${INCLUDE_DIRS}
      DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()
