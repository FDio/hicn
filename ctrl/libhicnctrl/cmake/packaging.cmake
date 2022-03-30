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

set(${LIBHICNCTRL_COMPONENT}_DESCRIPTION
  "hicn control library"
  CACHE STRING "Description for deb/rpm package."
)

set(${LIBHICNCTRL_COMPONENT}-dev_DESCRIPTION
  "hicn control library headers"
  CACHE STRING "Description for deb/rpm package."
)

set(${LIBHICNCTRL_COMPONENT}_DEB_DEPENDENCIES
  ""
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBHICNCTRL_COMPONENT}-dev_DEB_DEPENDENCIES
  "${LIBHICNCTRL_COMPONENT} (= stable_version)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBHICNCTRL_COMPONENT}_RPM_DEPENDENCIES
  ""
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBHICNCTRL_COMPONENT}-dev_RPM_DEPENDENCIES
  "${LIBHICNCTRL_COMPONENT} = stable_version"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBHICNCTRL_COMPONENT_MODULES}_DEB_DEPENDENCIES
  "hicn-plugin (= stable_version)"
  CACHE STRING "Dependencies for deb/rpm package."
)

set(${LIBHICNCTRL_COMPONENT_MODULES}_RPM_DEPENDENCIES
  "hicn-plugin = stable_version"
  CACHE STRING "Dependencies for deb/rpm package."
)
