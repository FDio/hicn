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

set(${COMPONENT}_DESCRIPTION
  "Libmemif, shared memory interface"
  CACHE STRING "Description for deb/rpm package."
)

set(${COMPONENT}_DEB_DEPENDENCIES
  "" CACHE STRING "Dependencies for deb/rpm package."
)

set(${COMPONENT}_RPM_DEPENDENCIES
  "" CACHE STRING "Dependencies for deb/rpm package."
)

set(${COMPONENT}-dev_DESCRIPTION
  "Libmemif, shared memory interface header files"
  CACHE STRING "Description for deb/rpm package."
)

set(${COMPONENT}-dev_DEB_DEPENDENCIES
  "${COMPONENT} (>= stable_version)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${COMPONENT}-dev_RPM_DEPENDENCIES
  "${COMPONENT} >= stable_version"
  CACHE STRING "Dependencies for deb/rpm package."
)
