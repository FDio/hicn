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

######################
# Packages section
######################

set(lib${LIBHICN}_DESCRIPTION
"libhicn provides a support library coded in C \
designed to help developers embed Hybrid ICN (hICN) \
functionalities in their applications (eg. forwarder, \
socket API, etc"
  CACHE STRING "Description for deb/rpm package."
)

set(lib${LIBHICN}_DESCRIPTION ${${LIBHICN}_DESCRIPTION}
  CACHE STRING "Description for deb/rpm package."
)

set(lib${LIBHICN}-dev_DESCRIPTION ${${LIBHICN}_DESCRIPTION}
  CACHE STRING "Description for deb/rpm package."
)

set(lib${LIBHICN}-dev_DEB_DEPENDENCIES
	"libhicn (= stable_version)"
  CACHE STRING "Dependencies for deb/rpm package."
)


if (INTERNAL_ENVIRONMENT)
  include(CheckSafeC)
  CheckSafeC()
  set(lib${LIBHICN}-dev_DEB_DEPENDENCIES
    "${lib${LIBHICN}-dev_DEB_DEPENDENCIES}, ${SAFEC_DEPENDENCY}"
    CACHE STRING "Dependencies for deb/rpm package."
  )
endif()

set(lib${LIBHICN}-dev_RPM_DEPENDENCIES
  "libhicn = stable_version"
  CACHE STRING "Dependencies for deb/rpm package."
)
