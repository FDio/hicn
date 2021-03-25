# Copyright (c) 2021 Cisco and/or its affiliates.
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

# Locate the Wireshark library.
#
# This file is meant to be copied into projects that want to use Wireshark.
# It will search for WiresharkConfig.cmake, which ships with Wireshark
# and will provide up-to-date buildsystem changes. Thus there should not be
# any need to update FindWiresharkVc.cmake again after you integrated it into
# your project.
#
# This module defines the following variables:
# Wireshark_FOUND
# Wireshark_VERSION_MAJOR
# Wireshark_VERSION_MINOR
# Wireshark_VERSION_PATCH
# Wireshark_VERSION
# Wireshark_VERSION_STRING
# Wireshark_INSTALL_DIR
# Wireshark_PLUGIN_INSTALL_DIR
# Wireshark_LIB_DIR
# Wireshark_LIBRARY
# Wireshark_INCLUDE_DIR
# Wireshark_CMAKE_MODULES_DIR

find_package(Wireshark ${Wireshark_FIND_VERSION} QUIET NO_MODULE PATHS $ENV{HOME} /opt/Wireshark)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Wireshark CONFIG_MODE)
