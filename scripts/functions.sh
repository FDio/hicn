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

#!/bin/bash
set -euxo pipefail

APT_PATH=$(which apt-get) || true
apt_get=${APT_PATH:-"/usr/local/bin/apt-get"}

# Cmake executable
CMAKE_INSTALL_DIR="/opt/cmake"
export PATH=:${CMAKE_INSTALL_DIR}/bin:${PATH}

# Figure out what system we are running on
if [ -f /etc/os-release ]; then
  . /etc/os-release
else
  echo "ERROR: System configuration not recognized. Build failed"
  exit 1
fi

COLLECTD_SOURCE="https://github.com/collectd/collectd/releases/download/collectd-5.12.0/collectd-5.12.0.tar.bz2"

function install_collectd_headers() {
  curl -OL ${COLLECTD_SOURCE}
  tar -xf collectd-5.12.0.tar.bz2

  pushd collectd-5.12.0
  ./configure && make -j$(nproc)
  popd

  export COLLECTD_HOME=${PWD}/collectd-5.12.0/src
}

# Call a function once
function call_once() {
  # OP_NAME is the name of the function
  OP_NAME=${1}
  # If function was already called return
  [[ -f /tmp/${OP_NAME} ]] && return 0
  # Otherwise call the function
  ${@}
  # And mark the function as called if no error occurred
  echo ${OP_NAME} >/tmp/${OP_NAME}
}

# Install dependencies
function install_deps() {
  make -C ${SCRIPT_PATH}/.. deps
}

function setup() {
  echo DISTRIBUTION: ${PRETTY_NAME}
  # export variables depending on the platform we are running
  call_once install_deps
  call_once install_collectd_headers
}

function setup_extras() {
  echo DISTRIBUTION: ${PRETTY_NAME}
  # export variables depending on the platform we are running

  call_once install_deps
  call_once install_collectd_headers
}
