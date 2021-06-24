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

list(APPEND TESTS
  test_auth
  test_consumer_producer_rtc
  test_core_manifest
  test_event_thread
  test_fec_reedsolomon
  test_interest
  test_packet
)

foreach(test ${TESTS})
    build_executable(${test}
        NO_INSTALL
        SOURCES ${test}.cc
        LINK_LIBRARIES ${LIBTRANSPORT_SHARED} ${GTEST_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
        INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS} ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS} ${GTEST_INCLUDE_DIRS}
        DEPENDS gtest ${LIBTRANSPORT_SHARED}
        COMPONENT lib${LIBTRANSPORT}
        DEFINITIONS "${COMPILER_DEFINITIONS}"
        LINK_FLAGS ${LINK_FLAGS}
    )

    add_test_internal(${test})
endforeach()
