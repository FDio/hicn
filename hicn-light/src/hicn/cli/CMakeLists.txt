# Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

if (NOT DISABLE_EXECUTABLES)

    list(APPEND CONTROLLER_SRC
        color.c
        hicnc.c
    )

    build_executable(${HICN_LIGHT_CONTROL}
        SOURCES ${CONTROLLER_SRC}
#LINK_LIBRARIES -Wl,--whole-archive ${LIBHICN_LIGHT_STATIC} -Wl,--no-whole-archive ${LIBHICNCTRL_STATIC}
        LINK_LIBRARIES ${LIBHICN_LIGHT_SHARED} ${LIBHICNCTRL_STATIC}
        DEPENDS ${LIBHICN_LIGHT_STATIC}
        COMPONENT ${HICN_LIGHT}
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )

    list(APPEND SHELL_SRC
        color.c
        hicns.c
    )

    # XXX here linking to libhicnctrl should be sufficient
    build_executable(${HICN_LIGHT_SHELL}
        SOURCES ${SHELL_SRC}
        LINK_LIBRARIES ${LIBHICN_LIGHT_SHARED} ${LIBHICNCTRL_STATIC}
        DEPENDS ${LIBHICN_LIGHT_STATIC}
        COMPONENT ${HICN_LIGHT}
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )

    list(APPEND DAEMON_SRC
        color.c
        hicnd.c
    )

    build_executable(${HICN_LIGHT_DAEMON}
        SOURCES ${DAEMON_SRC}
        LINK_LIBRARIES ${LIBHICN_LIGHT_SHARED} ${LIBHICNCTRL_STATIC}
        DEPENDS ${LIBHICN_LIGHT_STATIC}
        COMPONENT ${HICN_LIGHT}
        DEFINITIONS ${COMPILER_DEFINITIONS}
    )
endif ()
