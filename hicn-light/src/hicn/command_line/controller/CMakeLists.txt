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

list(APPEND CONTROLLER_SRC
  hicnLightControl_main.c
)

if (WIN32)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:\"LIBCMT\"" )
endif()

if (NOT DISABLE_EXECUTABLES)
  if (${CMAKE_SYSTEM_NAME} MATCHES Android)
    set(LINK_FLAGS "-Wl,--unresolved-symbols=ignore-in-object-files")
  endif()

  build_executable(${HICN_LIGHT_CONTROL}
    SOURCES ${CONTROLLER_SRC}
    LINK_LIBRARIES ${LIBHICN_LIGHT_STATIC}
    DEPENDS ${LIBHICN_LIGHT_STATIC}
    COMPONENT ${HICN_LIGHT}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    LINK_FLAGS ${LINK_FLAGS}
  )
endif ()
