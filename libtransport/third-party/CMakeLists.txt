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

set (THIRD_PARTY_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})

option(ENABLE_RELY "Enable download/build of rely library" OFF)

if (ENABLE_RELY)
  ##################################
  # Download librely

  if (INTERNAL_ENVIRONMENT)
    include(SetRelyGitRepo)
    SetRelyGitRepo()
  else()
    if(DEFINED ENV{GITHUB_USERNAME} AND DEFINED ENV{GITHUB_PASSWORD})
      set(GIT_REPO https://$ENV{GITHUB_USERNAME}:$ENV{GITHUB_PASSWORD}@github.com/steinwurf/rely.git)
    else()
      set(GIT_REPO ssh://github.com/steinwurf/rely.git)
    endif()
  endif()

  FetchContent_Declare(
    rely
    GIT_REPOSITORY ${GIT_REPO}
    GIT_TAG release/latest
    GIT_SHALLOW
    GIT_PROGRESS
    EXCLUDE_FROM_ALL
  )

  set(ENABLE_PIC ON)
  FetchContent_GetProperties(rely)
  if(NOT rely_POPULATED)
    pr("Download and build" "rely")
    FetchContent_Populate(rely)
    add_subdirectory(${rely_SOURCE_DIR} ${rely_BINARY_DIR} EXCLUDE_FROM_ALL)
  endif()

  list(APPEND THIRD_PARTY_INCLUDE_DIRS
    ${rely_BINARY_DIR}
    ${rely_SOURCE_DIR}/src
  )

  # Get rely libraries
  get_property(steinwurf_object_libraries GLOBAL
               PROPERTY steinwurf::object_libraries)

  foreach(rely_library ${steinwurf_object_libraries})
    list(APPEND THIRD_PARTY_OBJECT_LIBRARIES
      $<TARGET_OBJECTS:${rely_library}>
    )
  endforeach()

  list(APPEND THIRD_PARTY_DEPENDENCIES
    rely
  )
endif()

FetchContent_Declare(
  glog
  URL https://github.com/google/glog/archive/refs/tags/v0.5.0.zip
  PATCH_COMMAND patch -p1 CMakeLists.txt ${CMAKE_CURRENT_SOURCE_DIR}/glog.patch
  EXCLUDE_FROM_ALL
)

FetchContent_GetProperties(glog)
if(NOT glog_POPULATED)
  pr("Download and build" "glog")
  FetchContent_Populate(glog)
  set(WITH_GFLAGS OFF)
  set(WITH_GTEST OFF)
  set(WITH_UNWIND OFF)
  set(BUILD_TESTING OFF)
  add_subdirectory(${glog_SOURCE_DIR} ${glog_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

list(APPEND THIRD_PARTY_INCLUDE_DIRS
  ${glog_BINARY_DIR}
  ${glog_SOURCE_DIR}/src
)

list(APPEND THIRD_PARTY_OBJECT_LIBRARIES
  $<TARGET_OBJECTS:glog>
)

list(APPEND THIRD_PARTY_DEPENDENCIES
  glog
)

if(UNIX AND (NOT APPLE) AND (NOT ${CMAKE_SYSTEM_NAME} MATCHES Android))
  ##############################################################
  # Get memif version
  ##############################################################
  list(GET LIBMEMIF_DEFAULT_VERSION 0 MEMIF_VERSION)

  FetchContent_Declare(
    memif
    GIT_REPOSITORY https://github.com/FDio/vpp
    GIT_TAG v${MEMIF_VERSION}
    GIT_SHALLOW
    GIT_PROGRESS
    PATCH_COMMAND git apply ${CMAKE_CURRENT_SOURCE_DIR}/memif.patch
    EXCLUDE_FROM_ALL
  )

  FetchContent_GetProperties(memif)
  if(NOT memif_POPULATED)
    FetchContent_Populate(memif)
    add_subdirectory(${memif_SOURCE_DIR}/extras/libmemif ${memif_BINARY_DIR} EXCLUDE_FROM_ALL)
  endif()

  list(APPEND THIRD_PARTY_INCLUDE_DIRS
    ${memif_BINARY_DIR}
    ${memif_SOURCE_DIR}/extras/libmemif/src
  )

  list(APPEND THIRD_PARTY_OBJECT_LIBRARIES
    $<TARGET_OBJECTS:memif>
  )

  list(APPEND THIRD_PARTY_DEPENDENCIES
    memif
  )
endif()

set (THIRD_PARTY_LIBRARIES ${THIRD_PARTY_LIBRARIES} PARENT_SCOPE)
set (THIRD_PARTY_OBJECT_LIBRARIES ${THIRD_PARTY_OBJECT_LIBRARIES} PARENT_SCOPE)
set (THIRD_PARTY_INCLUDE_DIRS ${THIRD_PARTY_INCLUDE_DIRS} PARENT_SCOPE)
set (THIRD_PARTY_DEPENDENCIES ${THIRD_PARTY_DEPENDENCIES} PARENT_SCOPE)
