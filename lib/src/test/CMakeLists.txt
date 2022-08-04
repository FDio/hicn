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

find_package(Threads REQUIRED)

##############################################################
# Test sources
##############################################################
list(APPEND TESTS_SRC
  main.cc
  test_name.cc
  test_new_header.cc
  test_udp_header.cc
  test_validation.cc
  test_bitmap.cc
  test_interest_manifest.cc
  test_khash.cc
  test_pool.cc
  test_ring.cc
  test_vector.cc
)

##############################################################
# Build single unit test executable and add it to test list
##############################################################
build_executable(lib_tests
  NO_INSTALL
  SOURCES ${TESTS_SRC}
  LINK_LIBRARIES
    PRIVATE ${LIBHICN_STATIC}
    PRIVATE ${GTEST_LIBRARIES}
    PRIVATE ${CMAKE_THREAD_LIBS_INIT}
  INCLUDE_DIRS
    PRIVATE ${Libhicn_INCLUDE_DIRS}
    PRIVATE ${GTEST_INCLUDE_DIRS}
  DEPENDS gtest ${LIBHICN_SHARED}
  COMPONENT ${LIBHICN_COMPONENT}
  DEFINITIONS ${COMPILER_DEFINITIONS}
  COMPILE_OPTIONS ${DEFAULT_COMPILER_OPTIONS}
  LINK_FLAGS ${LINK_FLAGS}
)

add_test_internal(lib_tests)
