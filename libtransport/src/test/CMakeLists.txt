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
  test_aggregated_header.cc
  #######test_auth.cc
  # test_consumer_producer_rtc.cc
  test_core_manifest.cc
  # test_event_thread.cc
  test_fec_base_rs.cc
  test_fec_reedsolomon.cc
  test_fixed_block_allocator.cc
  test_indexer.cc
  test_interest.cc
  test_packet.cc
  test_packet_allocator.cc
  test_quality_score.cc
  test_sessions.cc
  test_thread_pool.cc
  test_quadloop.cc
  test_prefix.cc
)

if (ENABLE_RELY)
  list(APPEND TESTS_SRC
    test_fec_rely_wrapper.cc
    test_fec_base_rely.cc
  )
endif()

#if (UNIX AND NOT APPLE)
#  list(APPEND TESTS_SRC
#    test_memif_connector.cc
#  )
#endif()


##############################################################
# Link libraries
##############################################################
set(MEMIF_MODULE_LIBRARIES
  ${LIBRARIES}
  ${LIBTRANSPORT_SHARED}
  ${GTEST_LIBRARIES}
)


##############################################################
# Build single unit test executable and add it to test list
##############################################################
build_executable(libtransport_tests
    NO_INSTALL
    SOURCES ${TESTS_SRC}
    LINK_LIBRARIES
      ${MEMIF_MODULE_LIBRARIES}
    INCLUDE_DIRS
      $<TARGET_PROPERTY:${LIBTRANSPORT_SHARED},INCLUDE_DIRECTORIES>
      ${GTEST_INCLUDE_DIRS}
    DEPENDS gtest ${LIBTRANSPORT_SHARED}
    COMPONENT ${LIBTRANSPORT_COMPONENT}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
    LINK_FLAGS ${LINK_FLAGS}
)

add_test_internal(libtransport_tests)
