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

# Download artifacts of this patchset from jenkins
function download_artifacts() {
  if [[ -n ${GERRIT_URL:-} ]] &&
    [[ -n ${GERRIT_CHANGE_NUMBER:-} ]] &&
    [[ -n ${GERRIT_PATCHSET_NUMBER:-} ]]; then

    # Retrieve the Jenkins URL of the build relative to this PATCHSET
    JENKINS_URL=$(curl -s "https://${GERRIT_HOST}/r/changes/${GERRIT_CHANGE_NUMBER}/detail" | tail -n +2 | jq '.messages[].message?' | grep -E "Patch Set ${GERRIT_PATCHSET_NUMBER}:.*hicn-docs-verify.*SUCCESS" | grep -Eo 'https?://jenkins.fd.io/[^ ]+')

    # Download artifacts

  fi

}

# Run functional tests
function functional_test() {
  echo "*******************************************************************"
  echo "********************* STARTING FUNCTIONAL TESTS *******************"
  echo "*******************************************************************"

  sudo pip3 install robotframework

  # Run functional tests
  pushd ${SCRIPT_PATH}/../tests
    bash -x ./config.sh build setup 2-nodes hicn-light
    docker logs hicn-light-server
    docker logs hicn-light-client
    bash -x config.sh start hicn-light requin
  popd

  echo "*******************************************************************"
  echo "**********  FUNCTIONAL TESTS COMPLETED SUCCESSFULLY ***************"
  echo "*******************************************************************"
}
