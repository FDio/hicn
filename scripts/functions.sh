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

declare -a TEST_COMPONENTS=(
  "libtransport"
  "lib"
  "hicn_light"
  "hicnplugin"
  "libhicnctrl"
)

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
  if [[ -n ${GERRIT_HOST:-} ]] &&
    [[ -n ${GERRIT_CHANGE_NUMBER:-} ]] &&
    [[ -n ${GERRIT_PATCHSET_NUMBER:-} ]] &&
    [[ -n ${STREAM:-} ]]; then

    # Retrieve the Jenkins URL of the build relative to this PATCHSET
    JENKINS_URLS=$(
      curl -s "https://${GERRIT_HOST}/r/changes/${GERRIT_CHANGE_NUMBER}/detail" |
        tail -n +2 | jq '.messages[].message?' |
        grep -E "Patch Set ${GERRIT_PATCHSET_NUMBER}:.*hicn-verify-build.*build_success-hicn-ubuntu2004-$(uname -m)" |
        grep -Eo "https?://jenkins.fd.io/job/hicn-verify-build-${STREAM}-ubuntu2004-$(uname -m)[^ ]+"
    )

    # Transform string to array and get last
    JENKINS_URLS_ARRAY=(${JENKINS_URLS})
    ARTIFACTS_URL="${JENKINS_URLS_ARRAY[-1]}/artifact/packages/*zip*/packages.zip"

    # Download artifacts
    curl -o "${SCRIPT_PATH}/../packages.zip" -L "${ARTIFACTS_URL}"

    # Unzip them
    unzip "${SCRIPT_PATH}/../packages.zip" -d "${SCRIPT_PATH}/.."

    return 0
  fi

  # Fall back to image re-build if artifacts cannot be downloaded
  echo "GERRIT_* environment is not set. Image will be rebuilt from scratch" >&2
  return 1
}

function is_selinuxenabled() {
  sudo selinuxenabled && return 1 || return 0
}

# Run functional tests
function functional_test() {
  echo "*******************************************************************"
  echo "********************* STARTING FUNCTIONAL TESTS *******************"
  echo "*******************************************************************"

  if download_artifacts; then
    local build_sw=0
    local dockerfile_path="tests/Dockerfile.ci"
  else
    local build_sw=1
    local dockerfile_path="Dockerfile.dev"
  fi

  # Run functional tests
  pushd "${SCRIPT_PATH}/../tests"
    # If selinux, let's run the tests with a privileged container to bypass
    # the checks, which cost also in performance
    if is_selinuxenabled; then
        local privileged=false
    else
        local privileged=true
    fi

    BUILD_SOFTWARE=${build_sw} DOCKERFILE=${dockerfile_path} TEST_PRIVILEGED=${privileged} bash ./run-functional.sh
  popd

  echo "*******************************************************************"
  echo "**********  FUNCTIONAL TESTS COMPLETED SUCCESSFULLY ***************"
  echo "*******************************************************************"
}
