# Copyright (c) 2021-2022 Cisco and/or its affiliates.

include(BuildMacros)

list(APPEND TESTS_SRC
  test-configuration.cc
  test-fib.cc
  test-loop.cc
  test-parser.cc
  test-ctrl.cc
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
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ctrl/libhicnctrl/src/commands/command_listener.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ctrl/libhicnctrl/src/commands/command_route.c
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
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
)

add_test_internal(hicn_light_tests)
