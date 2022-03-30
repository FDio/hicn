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

set(${HICN_PLUGIN}_DESCRIPTION
  "A high-performance Hybrid ICN forwarder as a plugin to VPP."
  CACHE STRING "Description for deb/rpm package."
)

string(REGEX REPLACE "([0-9]+).([0-9]+)(.[0-9]+)?" "\\1\\2" VER_NO_DOTS ${VPP_DEFAULT_VERSION})

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/scripts/postinst
"#!/bin/bash

#########################################################
# Complete VPP config file with hicn configuration
#########################################################

if [ -e /etc/vpp/startup.conf ]; then
    RESULTS=$(sed -n '/hicn[ ]*{/p' /etc/vpp/startup.conf | wc -l)
    if [[ $RESULTS = 0 ]]; then
        printf '\n hicn {
            ## Set PIT size. Default is 131072 entries
            # pit-size 500000
            #
            ## Set CS size. Default is 4096
            # cs-size 50000
            #
            ## Set maximum PIT entries lifetime in milliseconds. Assigned to a PIT entry in case an interest carries a bigger lifetime
            # pit-lifetime-max 20
            #
            ## Percentage of CS to reserve for application producer faces
            # cs-reserved-app 20\n}' >> /etc/vpp/startup.conf
    fi;
fi;
")

set(${HICN_PLUGIN}_DEB_DEPENDENCIES
  "${LIBHICN_COMPONENT} (= stable_version), vpp (>= ${PREFIX_VERSION}), vpp-plugin-core (>= ${PREFIX_VERSION})"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${HICN_PLUGIN}-dev_DEB_DEPENDENCIES
  "${LIBHICN_COMPONENT}-dev (= stable_version), vpp-dev (>= ${PREFIX_VERSION}), libvppinfra-dev (>= ${PREFIX_VERSION})"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${HICN_PLUGIN}_DEB_PACKAGE_CONTROL_EXTRA
  "${CMAKE_CURRENT_BINARY_DIR}/scripts/postinst"
  CACHE STRING "Control scripts conffiles, postinst, postrm, prerm."
)
