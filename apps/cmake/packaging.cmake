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

set(${HICN_APPS}_DESCRIPTION
"Hicn apps provide the higet application, \
useful for testing and debugging within a hicn network."
  CACHE STRING "Description for deb/rpm package."
)

set(${HICN_APPS}_DEB_DEPENDENCIES
  "lib${LIBTRANSPORT} (= stable_version), lib${LIBHICNCTRL} (= stable_version)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${HICN_APPS}-dev_DEB_DEPENDENCIES
  "${HICN_APPS} (= stable_version), lib${LIBTRANSPORT}-dev (= stable_version), lib${LIBHICNCTRL}-dev (= stable_version)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${HICN_APPS}_RPM_DEPENDENCIES
  "lib${LIBTRANSPORT} = stable_version, lib${LIBHICNCTRL} = stable_version"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${HICN_APPS}-dev_RPM_DEPENDENCIES
  "${HICN_APPS} = stable_version, lib${LIBTRANSPORT}-dev = stable_version, lib${LIBHICNCTRL}-dev = stable_version"
  CACHE STRING "Dependencies for deb/rpm package."
)

if (INTERNAL_ENVIRONMENT)
  include(CheckSsl)
  CheckSsl()
  set(${HICN_APPS}_DEB_DEPENDENCIES
    "${${HICN_APPS}_DEB_DEPENDENCIES}, ${OPENSSL_DEPENDENCY}"
    CACHE STRING "Dependencies for deb/rpm package."
  )
  set(${HICN_APPS}-dev_DEB_DEPENDENCIES
    "${${HICN_APPS}-dev_DEB_DEPENDENCIES}, ${OPENSSL_DEPENDENCY_DEV}"
    CACHE STRING "Dependencies for deb/rpm package."
  )
endif ()