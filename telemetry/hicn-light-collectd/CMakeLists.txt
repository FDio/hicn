# Copyright (c) 2022 Cisco and/or its affiliates.

##############################################################
# Source files
##############################################################
list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light.c
)


##############################################################
# Include dirs
##############################################################
list(APPEND INCLUDE_DIRS
  ${COLLECTD_INCLUDE_DIRS}
  ${THIRD_PARTY_INCLUDE_DIRS}
)


##############################################################
# Libraries
##############################################################
find_package(Libhicn ${CURRENT_VERSION} REQUIRED NO_MODULE)
find_package(Libhicnctrl ${CURRENT_VERSION} REQUIRED NO_MODULE)

if (DISABLE_SHARED_LIBRARIES)
  set(LIBTYPE static)
else()
  set(LIBTYPE shared)
endif()

list(APPEND LIBHICN_LIBRARIES hicn::hicn.${LIBTYPE})
list(APPEND LIBHICNCTRL_LIBRARIES hicn::hicnctrl.${LIBTYPE})

list (APPEND LIBRARIES
  PRIVATE ${LIBHICNCTRL_LIBRARIES}
  PRIVATE ${LIBHICN_LIBRARIES}
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
build_library(${HICN_LIGHT_TELEMETRY}
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