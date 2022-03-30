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

##############################################################
# Get VPP version
##############################################################
list(GET VPP_DEFAULT_VERSION 0 VPP_VERSION)

set(hicn-sysrepo-plugin_DESCRIPTION
  "A Plugin to enable hICN VPP in sysrepo."
  CACHE STRING "Description for deb/rpm package."
)

set(hicn-sysrepo-plugin_DEB_DEPENDENCIES
  "hicn-plugin (= ${VPP_VERSION}-release), sysrepo (>= 1.0)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(hicn-sysrepo-plugin_RPM_DEPENDENCIES
  "hicn-plugin = ${VPP_VERSION}-release, sysrepo >= 1.0"
  CACHE STRING "Dependencies for deb/rpm package."
)
