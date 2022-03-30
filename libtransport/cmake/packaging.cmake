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

# Generate DEB / RPM packages

######################
# Packages section
######################

set(${LIBTRANSPORT_COMPONENT}_DESCRIPTION
"Libhicn-transport provides transport services and \
socket API for applications willing to communicate \
using the hICN protocol stack."
  CACHE STRING "Description for deb/rpm package."
)

set(${LIBTRANSPORT_COMPONENT}-dev_DESCRIPTION
  CACHE STRING "Header files for developing using libhicntransport."
)

set(lib${LIBTRANSPORT}-devel_DESCRIPTION
  CACHE STRING "Header files for developing using libhicntransport."
)

set(${LIBTRANSPORT_COMPONENT}-io-modules_DESCRIPTION
  CACHE STRING "Additional io modules for libhicntransport, including the memif connector for vpp."
)

set(${LIBTRANSPORT_COMPONENT}_DEB_DEPENDENCIES
  "lib${LIBHICN} (= stable_version), libconfig++9v5 (>= 1.5-0.4build1)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBTRANSPORT_COMPONENT}_RPM_DEPENDENCIES
  "lib${LIBHICN} = stable_version, libconfig >= 1.5-9.el8"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBTRANSPORT_COMPONENT}-dev_DEB_DEPENDENCIES
  "${LIBTRANSPORT_COMPONENT} (= stable_version), libasio-dev (>= 1.10), lib${LIBHICN}-dev (= stable_version), libconfig++-dev (>= 1.5-0.4build1)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBTRANSPORT_COMPONENT}-dev_RPM_DEPENDENCIES
  "${LIBTRANSPORT_COMPONENT} = stable_version, asio-devel >= 1.10, lib${LIBHICN}-devel = stable_version, libconfig-devel >= 1.5-9.el8"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBTRANSPORT_COMPONENT}-io-modules_DEB_DEPENDENCIES
  "${LIBTRANSPORT_COMPONENT} (= stable_version), vpp (>= ${PREFIX_VERSION}), hicn-plugin (= stable_version)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBTRANSPORT_COMPONENT}-io-modules_RPM_DEPENDENCIES
  "${LIBTRANSPORT_COMPONENT} = stable_version, vpp >= ${PREFIX_VERSION}, hicn-plugin = stable_version"
  CACHE STRING "Dependencies for deb/rpm package."
)

if (INTERNAL_ENVIRONMENT)
  include(CheckSsl)
  CheckSsl()
  set(${LIBTRANSPORT_COMPONENT}_DEB_DEPENDENCIES
    "${${LIBTRANSPORT_COMPONENT}_DEB_DEPENDENCIES}, ${OPENSSL_DEPENDENCY}"
    CACHE STRING "Dependencies for deb/rpm package."
  )
  set(${LIBTRANSPORT_COMPONENT}-dev_DEB_DEPENDENCIES
    "${${LIBTRANSPORT_COMPONENT}-dev_DEB_DEPENDENCIES}, ${OPENSSL_DEPENDENCY_DEV}"
    CACHE STRING "Dependencies for deb/rpm package."
  )
endif ()
