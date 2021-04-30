# Copyright (c) 2019 Cisco and/or its affiliates.
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

########################################
#
# Find the LongBow libraries and includes
# This module sets:
#  SYSTEMD_FOUND: True if Systemd was found
#  SYSTEMD_SERVICES_INSTALL_DIR:  The Systemd install directory

set(SYSTEMD_SERVICE_FOLDER "/lib/systemd/system")

macro(install_service_script script)
cmake_parse_arguments(ARG
  ""
  "COMPONENT"
  ""
  ${ARGN}
)

  # Install service file only if
  # 1) We are on a linux system
  # 2) The installation prefix is /usr

  if (NOT ARG_COMPONENT)
    set(ARG_COMPONENT hicn)
  endif()

  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" AND ${CMAKE_INSTALL_PREFIX} STREQUAL "/usr")
    install (FILES ${script} DESTINATION ${SYSTEMD_SERVICE_FOLDER} COMPONENT ${ARG_COMPONENT})
  endif()
endmacro(install_service_script)
