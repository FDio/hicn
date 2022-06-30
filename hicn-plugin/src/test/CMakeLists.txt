# Copyright (c) 2022 Cisco and/or its affiliates.
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

#############################################################
# Dependencies
#############################################################

# We need a pure C test framework for the hicn-plugin.
include (UnityTestFrameworkImport)
find_package(Threads REQUIRED)

##############################################################
# Test sources
##############################################################
list(APPEND TESTS_SRC
  main.c
  vpp.c
  test_pcs.c
)


##############################################################
# Link libraries
##############################################################
set(TEST_LIBRARIES
  ${VPP_LIBRARIES}
  ${UNITY_LIBRARIES}
  ${LIBHICN_SHARED}
  ${HICNPLUGIN_SHARED}
  Threads::Threads
)

set (
  LINK_FLAGS
  "-Wl,-unresolved-symbols=ignore-all"
)


##############################################################
# Build single unit test executable and add it to test list
##############################################################
build_executable(hicnplugin_tests
    NO_INSTALL
    SOURCES ${TESTS_SRC}
    LINK_LIBRARIES
      ${TEST_LIBRARIES}
    INCLUDE_DIRS
      $<TARGET_PROPERTY:${HICNPLUGIN_SHARED},INCLUDE_DIRECTORIES>
      ${UNITY_INCLUDE_DIRS}
    DEPENDS unity ${HICNPLUGIN_SHARED}
    COMPONENT ${HICN_PLUGIN}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
    LINK_FLAGS ${LINK_FLAGS}
)

unity_add_test_internal(hicnplugin_tests)
