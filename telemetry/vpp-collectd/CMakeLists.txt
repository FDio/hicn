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

##############################################################
# Dependencies
##############################################################
find_package(Vpp ${VPP_DEFAULT_VERSION} REQUIRED)


##############################################################
# Compiler Options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)


##############################################################
# Subdirectories
##############################################################
add_subdirectory(vpp)
add_subdirectory(vpp-hicn)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
	make_packages()
endif()
