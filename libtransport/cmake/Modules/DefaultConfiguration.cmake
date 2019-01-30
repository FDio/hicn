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

# C/c++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)

# Compilation options
option(BUILD_APPS "Build apps" ON)
option(BUILD_WITH_VPP "Add support for VPP" OFF)
option(COMPILE_TESTS "Compile functional tests" OFF)

# Compilation flags

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fpermissive")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -fpermissive")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -fpermissive")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL}")

# Packaging
# TODO Libasio and libmemif
set(DEPS_DEB "libparc (>= 1.0)")
set(DEPS_RPM "libparc >= 1.0")
set(BUILD_DEPS_DEB "libtransport (>= 1.0), libhicn-dev (>= 1.0), libparc-dev (>= 1.0)")
set(BUILD_DEPS_RPM "libtransport >= 1.0, libhicn-devel >= 1.0, libparc-devel >= 1.0")

set(VPP_DEPS_DEB "${DEPS_DEB}, hicn-plugin, vpp-lib (>= 18.07), vpp-dev (>= 18.07)")
set(VPP_DEPS_RPM "${DEPS_RPM}, hicn-plugin, vpp-lib >= 18.07), vpp-dev (>= 18.07)")
set(VPP_BUILD_DEPS_DEB "${BUILD_DEPS_DEB}, hicn-plugin, vpp-lib (>= 18.07), vpp-dev (>= 18.07)")
set(VPP_BUILD_DEPS_RPM "${BUILD_DEPS_RPM}, hicn-plugin, vpp-lib (>= 18.07), vpp-dev (>= 18.07)")

set(PACKAGE_DESCRIPTION "This library is designed to provide a transport layer and API for applications willing to communicate using an hICN protocol stack.")
set(PACKAGE_HOMEPAGE "https://wiki.fd.io/view/Libicnet")