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

set(sysrepo_DESCRIPTION
"Sysrepo is a YANG-based configuration and operational datastore." 
  CACHE STRING "Description for deb/rpm package."
)

set(sysrepo_DEB_DEPENDENCIES
    "libpcre3 (>= 2:8.39-9), libev4 (>= 1:4.22-1), libprotobuf-c1 (>= 1.2.1-2), libyang (>= 0.16-r2-1), libavl1 (>=0.3.5-4)"
    CACHE STRING "Dependencies for deb/rpm package."
)

set(sysrepo_RPM_DEPENDENCIES
    "libpcre3 (>= 2:8.39-9), libev4 (>= 1:4.22-1), libprotobuf-c1 (>= 1.2.1-2), libyang (>= 0.16-r2-1), libavl1 (>=0.3.5-4)"
    CACHE STRING "Dependencies for deb/rpm package."
)


