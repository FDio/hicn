# Copyright (c) 2021 Cisco and/or its affiliates.
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
list(APPEND APPS_SRC
  higet.cc
)


##############################################################
# Linker flags
##############################################################
if (WIN32)
  set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:\"LIBCMT\""
  )
endif()


##############################################################
# Compiler options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)


##############################################################
# Build higet
##############################################################
if (NOT DISABLE_EXECUTABLES)
  build_executable(${HIGET}
    SOURCES ${APPS_SRC}
    LINK_LIBRARIES
      ${LIBHICN_LIBRARIES}
      ${LIBTRANSPORT_LIBRARIES}
      ${CMAKE_THREAD_LIBS_INIT}
      ${WSOCK32_LIBRARY}
      ${WS2_32_LIBRARY}
    DEPENDS ${LIBTRANSPORT_LIBRARIES}
    COMPONENT ${HICN_APPS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    LINK_FLAGS ${LINK_FLAGS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )
endif ()
