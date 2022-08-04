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

##############################################################
# Test sources
##############################################################
list(APPEND TESTS_SRC
  main.cc
  common.cc
  test_data.cc
  test_hicnlight_listener.cc
  test_hicnlight_connection.cc
  test_hicnlight_route.cc
  ../modules/hicn_light/connection.c
  ../modules/hicn_light/face.c
  ../modules/hicn_light/listener.c
  ../modules/hicn_light/route.c
)

##############################################################
# Build single unit test executable and add it to test list
##############################################################
build_executable(libhicnctrl_tests
    NO_INSTALL
    SOURCES ${TESTS_SRC}
    LINK_LIBRARIES
      ${LIBRARIES}
      ${LIBHICNCTRL_SHARED}
      ${GTEST_LIBRARIES}
      pthread
    INCLUDE_DIRS
    $<TARGET_PROPERTY:${LIBHICNCTRL_SHARED},INCLUDE_DIRECTORIES>
      ${GTEST_INCLUDE_DIRS}
    DEPENDS gtest ${LIBHICNCTRL_SHARED}
    COMPONENT ${LIBHICNCTRL_COMPONENT}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
    LINK_FLAGS ${LINK_FLAGS}
)

add_test_internal(libhicnctrl_tests)
