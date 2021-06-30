# Copyright (c) 2019 Cisco and/or its affiliates.
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
cmake_minimum_required(VERSION 3.10)
project(sysrepo)

list(APPEND MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules
)

string(REPLACE ";" "|" MODULE_PATH "${MODULE_PATH}")

include(ExternalProject)

ExternalProject_Add(sysrepo
  GIT_REPOSITORY https://github.com/sysrepo/sysrepo.git
  GIT_TAG devel
  GIT_SHALLOW TRUE
  DEPENDS libyang
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/sysrepo
  PATCH_COMMAND git apply ${CMAKE_CURRENT_SOURCE_DIR}/sysrepo.patch
  # Use the alternate list separator
  # (https://cmake.org/cmake/help/latest/manual/cmake-language.7.html#lists)
  LIST_SEPARATOR |
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_MODULE_PATH=${MODULE_PATH} -DBUILD_EXAMPLES=OFF -DCMAKE_PREFIX_PATH=${DESTDIR}/usr
  BUILD_COMMAND make package
  INSTALL_COMMAND make DESTDIR=${DESTDIR} install
)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(Packager)
    make_packages()
endif()