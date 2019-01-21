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

######################
# Packages section
######################

set(${LIBHICN_LIGHT}_DESCRIPTION
  "hicn-light is a socket based forwarder"
  CACHE STRING "Description for deb/rpm package."
)

set(${LIBHICN_LIGHT}_DEB_DEPENDENCIES
  "libhicn (>= 1.0), libparc (>= 1.0)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBHICN_LIGHT}_RPM_DEPENDENCIES
  "libhicn >= 1.0, libparc >= 1.0"
  CACHE STRING "Dependencies for deb/rpm package."
)