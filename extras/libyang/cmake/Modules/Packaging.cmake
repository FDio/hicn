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

set(libyang_DESCRIPTION
  "libyang is a YANG data modelling language parser and toolkit written (and providing API) in C."
  CACHE STRING "Description for deb/rpm package."
)

set(libyang_DEB_DEPENDENCIES
    "libpcre3 (>= 2:8.39-9)"
    CACHE STRING "Dependencies for deb/rpm package."
)

set(libyang_RPM_DEPENDENCIES
    "libpcre3 (>= >= 2:8.39-9)"
    CACHE STRING "Dependencies for deb/rpm package."
)
