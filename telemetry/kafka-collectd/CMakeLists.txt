# Copyright (c) 2022 Cisco and/or its affiliates.

##############################################################
# Source files
##############################################################
file(GLOB_RECURSE COLLECTD_UTILS_SOURCES "${THIRD_PARTY_INCLUDE_DIRS}/utils/cmds/*.c")

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/write_kafka_line_protocol.c
  ${THIRD_PARTY_INCLUDE_DIRS}/utils/format_json/format_json.c
  ${THIRD_PARTY_INCLUDE_DIRS}/utils/format_graphite/format_graphite.c
  ${CMAKE_CURRENT_SOURCE_DIR}/format_influxdb.c
  ${COLLECTD_UTILS_SOURCES}
)


##############################################################
# Include dirs
##############################################################
list(APPEND INCLUDE_DIRS
  PRIVATE ${COLLECTD_INCLUDE_DIRS}
  PRIVATE ${THIRD_PARTY_INCLUDE_DIRS}
)


##############################################################
# Libraries
##############################################################
find_package(RdKafka ${RDKAFKA_DEFAULT_VERSION} REQUIRED)
find_library(YAJL_LIB libyajl.so REQUIRED)

list (APPEND LIBRARIES
  ${YAJL_LIB}
  ${RdKafka_LIBRARY_PATH}
)


##############################################################
# Compiler options
##############################################################
list(APPEND COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
  ${COLLECTD_COMPILER_OPTIONS}
)


##############################################################
# Build library
##############################################################
build_library(${KAFKA_TELEMETRY}
  SHARED
  EMPTY_PREFIX
  SOURCES ${SOURCE_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  INCLUDE_DIRS
    PRIVATE ${INCLUDE_DIRS}
  INSTALL_FULL_PATH_DIR ${COLLECTD_PLUGIN_DIR}
  COMPONENT ${COLLECTD_PLUGINS}
  DEPENDS ${DEPENDENCIES}
  LINK_FLAGS ${LINK_FLAGS}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)
