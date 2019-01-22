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

# Generate DEB / RPM packages

######################
# Packages section
######################

set(lib${LIBTRANSPORT}_DESCRIPTION
"Libhicn-transport provides transport services and \
socket API for applications willing to communicate \
using the hICN protocol stack."
  CACHE STRING "Description for deb/rpm package."
)

set(lib${LIBTRANSPORT}-dev_DESCRIPTION ${lib${LIBTRANSPORT}_DESCRIPTION}
  CACHE STRING "Description for deb/rpm package.")
set(lib${LIBTRANSPORT}-devel_DESCRIPTION ${lib${LIBTRANSPORT}_DESCRIPTION}
  CACHE STRING "Description for deb/rpm package.")

if ((BUILD_MEMIF_CONNECTOR OR BUILD_VPP_PLUGIN) AND "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")

  set(lib${LIBTRANSPORT}_DEB_DEPENDENCIES
    "libhicn (>= 1.0), libparc (>= 1.0), vpp-lib (== 19.01-release)"
    CACHE STRING "Dependencies for deb/rpm package."
  )

  set(lib${LIBTRANSPORT}_RPM_DEPENDENCIES
    "libhicn >= 1.0, libparc >= 1.0, vpp-lib = 19.01-release"
    CACHE STRING "Dependencies for deb/rpm package."
  )

  set(lib${LIBTRANSPORT}-dev_DEB_DEPENDENCIES
    "libtransport (>= 1.0), libasio-dev (>= 1.10), libhicn-dev (>= 1.0), libparc-dev (>= 1.0), vpp-dev (== 19.01-release)"
    CACHE STRING "Dependencies for deb/rpm package."
  )

  set(lib${LIBTRANSPORT}-devel_RPM_DEPENDENCIES
    "libtransport >= 1.0, asio-devel >= 1.10, libhicn-devel >= 1.0, libparc-devel >= 1.0, vpp-devel = 19.01-release"
    CACHE STRING "Dependencies for deb/rpm package."
  )

else()

  set(lib${LIBTRANSPORT}_DEB_DEPENDENCIES
    "libhicn (>= 1.0), libparc (>= 1.0)"
    CACHE STRING "Dependencies for deb/rpm package."
  )

  set(lib${LIBTRANSPORT}_RPM_DEPENDENCIES
    "libhicn >= 1.0, libparc >= 1.0"
    CACHE STRING "Dependencies for deb/rpm package."
  )

  set(lib${LIBTRANSPORT}-dev_DEB_DEPENDENCIES
    "libtransport (>= 1.0), libasio-dev (>= 1.10), libhicn-dev (>= 1.0), libparc-dev (>= 1.0)"
    CACHE STRING "Dependencies for deb/rpm package."
  )

  set(lib${LIBTRANSPORT}-devel_RPM_DEPENDENCIES
    "libtransport >= 1.0, asio-devel >= 1.10, libhicn-devel >= 1.0, libparc-devel >= 1.0"
    CACHE STRING "Dependencies for deb/rpm package."
  )

endif()