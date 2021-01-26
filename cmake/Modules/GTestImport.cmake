# Copyright (c) 2020 Cisco and/or its affiliates.
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

##################################
# Download and install GoogleTest

include(ExternalProject)
ExternalProject_Add(gtest
  URL https://github.com/google/googletest/archive/v1.10.x.zip
  PREFIX ${CMAKE_BINARY_DIR}/gtest
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(gtest source_dir binary_dir)

message (STATUS "GTest include dir: ${source_dir}/googlemock/include ${source_dir}/googletest/include)")
message (STATUS "GTest libs: ${binary_dir}/lib/libgmock_main.a ${binary_dir}/lib/libgmock.a ${binary_dir}/lib/libgtest_main.a ${binary_dir}/lib/libgtest.a")

set(GTEST_INCLUDE_DIRS ${source_dir}/googlemock/include ${source_dir}/googletest/include)
set(GTEST_LIBRARIES ${binary_dir}/lib/libgmock_main.a ${binary_dir}/lib/libgmock.a ${binary_dir}/lib/libgtest_main.a ${binary_dir}/lib/libgtest.a)

macro(add_test_internal test)
  if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
    gtest_discover_tests(${test}-bin TEST_PREFIX new:)
  else()
    add_test(NAME ${test}-bin COMMAND ${test})
  endif()
endmacro(add_test_internal)

enable_testing()