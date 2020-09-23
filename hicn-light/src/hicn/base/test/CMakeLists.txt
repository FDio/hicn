# Copyright (c) 2017-2019 Cisco and/or its affiliates.

include(BuildMacros)

list(APPEND TESTS
  test-bitmap
  test-hash
  test-khash
  test-loop
  test-pool
  test-vector
)

foreach(test ${TESTS})
    build_executable(${test}
        NO_INSTALL
        SOURCES ${test}.cc
        LINK_LIBRARIES ${LIBHICN_LIGHT_SHARED} ${LIBHICNCTRL_SHARED} ${GTEST_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
        INCLUDE_DIRS ${HICN_LIGHT_INCLUDE_DIRS} ${GTEST_INCLUDE_DIRS}
        DEPENDS gtest ${LIBHICNCTRL_SHARED} ${LIBHICN_LIGHT_SHARED}
        COMPONENT ${HICN_LIGHT}
        DEFINITIONS "${COMPILER_DEFINITIONS}"
    )

    if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
        gtest_discover_tests(${test}-bin TEST_PREFIX new:)
    else()
        add_test(NAME ${test}-bin COMMAND ${test})
    endif()
endforeach()
