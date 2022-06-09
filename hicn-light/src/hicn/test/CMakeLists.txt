# Copyright (c) 2021 Cisco and/or its affiliates.

include(BuildMacros)

list(APPEND TESTS_SRC
  test-bitmap.cc
  test-configuration.cc
  test-hash.cc
  test-khash.cc
  test-loop.cc
  test-pool.cc
  test-parser.cc
  test-ctrl.cc
  test-ring.cc
  test-vector.cc
  test-interest_manifest.cc
  test-msgbuf_pool.cc
  test-nexthops.cc
  test-connection_table.cc
  test-listener_table.cc
  test-packet_cache.cc
  test-strategy-load-balancing.cc
  test-strategy-random.cc
  test-strategy-replication.cc
  test-strategy-best-path.cc
  test-subscription.cc
  test-local_prefixes.cc
  test-probe_generator.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/../config/command_listener.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../config/command_route.c
  main.cc
)

build_executable(hicn_light_tests
    NO_INSTALL
    SOURCES ${TESTS_SRC}
    LINK_LIBRARIES ${LIBHICN_LIGHT_STATIC} ${GTEST_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
    INCLUDE_DIRS ${HICN_LIGHT_INCLUDE_DIRS} ${GTEST_INCLUDE_DIRS}
    DEPENDS gtest ${LIBHICNCTRL_STATIC} ${LIBHICN_LIGHT_SHARED}
    COMPONENT ${HICN_LIGHT}
    DEFINITIONS "${COMPILER_DEFINITIONS}"
)

add_test_internal(hicn_light_tests)
