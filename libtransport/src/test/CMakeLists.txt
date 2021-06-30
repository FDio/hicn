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

include(BuildMacros)

list(APPEND TESTS_SRC
  main.cc
  test_auth.cc
  test_consumer_producer_rtc.cc
  test_core_manifest.cc
  test_event_thread.cc
  test_fec_reedsolomon.cc
  test_indexer.cc
  test_interest.cc
  test_packet.cc
)

if (ENABLE_RELY)
  list(APPEND TESTS_SRC
    test_fec_rely_wrapper.cc
  )
endif()

build_executable(unit_tests
    NO_INSTALL
    SOURCES ${TESTS_SRC}
    LINK_LIBRARIES
      ${LIBRARIES}
      ${LIBTRANSPORT_STATIC}
      ${GTEST_LIBRARIES}
    INCLUDE_DIRS
      ${LIBTRANSPORT_INCLUDE_DIRS}
      ${LIBHICN_INCLUDE_DIRS}
      ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
      ${GTEST_INCLUDE_DIRS}
    DEPENDS gtest ${LIBTRANSPORT_SHARED}
    COMPONENT ${LIBTRANSPORT_COMPONENT}
    DEFINITIONS "${COMPILER_DEFINITIONS}"
    LINK_FLAGS ${LINK_FLAGS}
)

add_test_internal(unit_tests)
