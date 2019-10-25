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

set(${HICN_LIGHT}_DESCRIPTION
  "hicn-light is a socket based forwarder"
  CACHE STRING "Description for deb/rpm package."
)

set(${HICN_LIGHT}_DEB_DEPENDENCIES
  "lib${LIBHICN} (>= stable_version), libparc (>= 1.0)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${HICN_LIGHT}_DEB_PACKAGE_CONTROL_EXTRA
  "${CMAKE_CURRENT_SOURCE_DIR}/config/postinst;${CMAKE_CURRENT_SOURCE_DIR}/config/postrm"
  CACHE STRING "Control scripts conffiles, postinst, postrm, prerm."
)

set(${HICN_LIGHT}_RPM_DEPENDENCIES
  "lib${LIBHICN} >= stable_version, libparc >= 1.0"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${HICN_LIGHT}_RPM_POST_INSTALL_SCRIPT_FILE
  "${CMAKE_CURRENT_SOURCE_DIR}/config/post"
  CACHE STRING "Install script that will be copied in the %post section"
)

set(${HICN_LIGHT}_RPM_POST_UNINSTALL_SCRIPT_FILE
  "${CMAKE_CURRENT_SOURCE_DIR}/config/postun"
  CACHE STRING "Install script that will be copied in the %post section"
)