# Copyright (c) 2021 Cisco and/or its affiliates.

include(BuildMacros)

list(APPEND TESTS
  test_transport_producer
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
    )

    add_test_internal(${test})
endforeach()