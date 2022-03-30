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


if (NOT DISABLE_EXECUTABLES)
##############################################################
# Force libhicn library to whole archive mode
##############################################################
  if (APPLE)
    set(
      LIBHICN_LIGHT_WHOLE_ARCHIVE
      "-Wl,-force_load"
      "${LIBHICN_LIGHT_STATIC}"
    )
  else()
    set(
      LIBHICN_LIGHT_WHOLE_ARCHIVE
      "-Wl,--whole-archive"
      "${LIBHICN_LIGHT_STATIC}"
      "-Wl,--no-whole-archive"
    )
  endif()

##############################################################
# Sources
##############################################################
  list(APPEND CONTROLLER_SRC
      color.c
      hicnc.c
  )


##############################################################
# Build hicn-light-control
##############################################################
  build_executable(${HICN_LIGHT_CONTROL}
    SOURCES ${CONTROLLER_SRC}
    LINK_LIBRARIES ${LIBHICN_LIGHT_WHOLE_ARCHIVE}
    DEPENDS ${LIBHICN_LIGHT_STATIC}
    COMPONENT ${HICN_LIGHT}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )


##############################################################
# Build hicn-light-shell
##############################################################
  list(APPEND SHELL_SRC
    color.c
    hicns.c
  )

  build_executable(${HICN_LIGHT_SHELL}
    SOURCES ${SHELL_SRC}
    LINK_LIBRARIES ${LIBHICN_LIGHT_WHOLE_ARCHIVE}
    DEPENDS ${LIBHICN_LIGHT_STATIC}
    COMPONENT ${HICN_LIGHT}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )


##############################################################
# Build hicn-light-shell
##############################################################
  list(APPEND DAEMON_SRC
    color.c
    hicnd.c
  )

  # hicn-light-daemon does not compile under Android due to bindSocket
  if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    build_executable(${HICN_LIGHT_DAEMON}
      SOURCES ${DAEMON_SRC}
      LINK_LIBRARIES ${LIBHICN_LIGHT_WHOLE_ARCHIVE}
      DEPENDS ${LIBHICN_LIGHT_STATIC}
      COMPONENT ${HICN_LIGHT}
      DEFINITIONS ${COMPILER_DEFINITIONS}
      COMPILE_OPTIONS ${COMPILER_OPTIONS}
    )
  endif ()
endif ()
