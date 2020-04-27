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
if (NOT DISABLE_EXECUTABLES)
  build_executable(${HICN_LIGHT_CONTROL}
    SOURCES ${CONTROLLER_SRC}
    LINK_LIBRARIES ${HICN_LIGHT_LINK_LIBRARIES}
    DEPENDS ${LIBHICN_LIGHT_STATIC}
    COMPONENT ${HICN_LIGHT}
    DEFINITIONS ${COMPILER_DEFINITIONS}
  )
endif ()
