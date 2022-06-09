# Copyright (c) 2022 Cisco and/or its affiliates.

set(THIRD_PARTY_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})

include(FetchContent)
set(FETCHCONTENT_QUIET off)
FetchContent_Declare(collectd
  URL https://github.com/collectd/collectd/archive/refs/tags/collectd-${COLLECTD_VERSION}.zip
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
)
FetchContent_Populate(collectd)

list(APPEND THIRD_PARTY_INCLUDE_DIRS
  ${collectd_SOURCE_DIR}/src
)
set(THIRD_PARTY_INCLUDE_DIRS ${THIRD_PARTY_INCLUDE_DIRS} PARENT_SCOPE)
