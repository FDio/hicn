# Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(extras)

list(APPEND CMAKE_MODULE_PATH
  ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules
)

set (DESTDIR ${CMAKE_BINARY_DIR}/extras-root)

# add_subdirectory(router-plugin)
add_subdirectory(libmemif)
# add_subdirectory(libyang)
# add_subdirectory(sysrepo)


if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  include(Packager)
  make_packages()
endif()