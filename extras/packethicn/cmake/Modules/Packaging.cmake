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

######################
# Packages section
######################

set(${PACKETHICN}_DESCRIPTION
  "packethicn is a Wireshark plugin that dissects HICN traffic"
  CACHE STRING "Description for deb/rpm package."
)

set(${PACKETHICN}_DEB_DEPENDENCIES
  "lib${LIBHICN} (>= stable_version), wireshark (>= ${Wireshark_VERSION}), wireshark (<< ${Wireshark_NEXT_VERSION})"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${PACKETHICN}_RPM_DEPENDENCIES
  "lib${LIBHICN} >= stable_version, wireshark >= ${Wireshark_VERSION}, wireshark < ${Wireshark_NEXT_VERSION}"
  CACHE STRING "Dependencies for deb/rpm package."
)