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
# Project and cmake version
##############################################################
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(ctrl)


##############################################################
# Subdirectories
##############################################################
add_subdirectory(libhicnctrl)
if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" OR "${CMAKE_SYSTEM_NAME}" STREQUAL "Android")
  add_subdirectory(facemgr)
endif ()