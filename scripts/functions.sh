# Copyright (c) 2020 Cisco and/or its affiliates.
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

APT_PATH=`which apt-get` || true
apt_get=${APT_PATH:-"/usr/local/bin/apt-get"}

# Cmake executable
CMAKE_INSTALL_DIR="/opt/cmake"
export PATH=:${CMAKE_INSTALL_DIR}/bin:${PATH}

PACKAGECLOUD_RELEASE_REPO_DEB="https://packagecloud.io/install/repositories/fdio/release/script.deb.sh"
PACKAGECLOUD_RELEASE_REPO_RPM="https://packagecloud.io/install/repositories/fdio/release/script.rpm.sh"
PACKAGECLOUD_HICN_REPO_DEB="https://packagecloud.io/install/repositories/fdio/hicn/script.deb.sh"
PACKAGECLOUD_HICN_REPO_RPM="https://packagecloud.io/install/repositories/fdio/hicn/script.rpm.sh"

VPP_GIT_REPO="https://github.com/FDio/vpp"
VPP_BRANCH="stable/2005"

    # Figure out what system we are running on
if [ -f /etc/os-release ]; then
    . /etc/os-release
else
    echo "ERROR: System configuration not recognized. Build failed"
    exit 1
fi

VERSION_REGEX="s/v([0-9]+).([0-9]+)(.*)?-([0-9]+)-(g[0-9a-f]+)/\1.\2-release/g"
VPP_VERSION_DEB="$(git describe --long --match "v*" | sed -E ${VERSION_REGEX}).1"
VPP_VERSION_RPM="${VPP_VERSION_DEB}.x86_64"

DEPS_UBUNTU=("build-essential"
             "doxygen"
             "curl"
             "cmake"
             "libasio-dev"
             "libconfig-dev"
             "libconfig++-dev"
             "libcurl4-openssl-dev"
             "libevent-dev"
             "libssl-dev"
             "ninja-build"
             "python3-ply")

DEPS_UBUNTU_PKGCLOUD=("libparc-dev"
                      "libmemif-dev"
                      "libmemif"
                      "vpp=${VPP_VERSION_DEB}"
                      "vpp-dev=${VPP_VERSION_DEB}"
                      "libvppinfra=${VPP_VERSION_DEB}"
                      "libvppinfra-dev=${VPP_VERSION_DEB}"
                      "vpp-plugin-core=${VPP_VERSION_DEB}"
                      "libparc-dev")

COLLECTD_SOURCE="https://github.com/collectd/collectd/releases/download/collectd-5.12.0/collectd-5.12.0.tar.bz2"

function install_collectd_headers() {
    curl -OL ${COLLECTD_SOURCE}
    tar -xf collectd-5.12.0.tar.bz2

    pushd collectd-5.12.0
        ./configure && make -j$(nproc)
    popd

    export COLLECTD_HOME=${PWD}/collectd-5.12.0/src
}

function setup_fdio_repo() {
    DISTRIB_ID=${ID}

    if [ "${DISTRIB_ID}" == "ubuntu" ]; then
        curl -s ${PACKAGECLOUD_RELEASE_REPO_DEB} | sudo bash
        curl -s ${PACKAGECLOUD_HICN_REPO_DEB} | sudo bash
    elif [ "${DISTRIB_ID}" == "centos" ]; then
        curl -s ${PACKAGECLOUD_RELEASE_REPO_RPM} | sudo bash
        curl -s ${PACKAGECLOUD_HICN_REPO_RPM} | sudo bash
    else
        echo "Distribution ${DISTRIB_ID} is not supported"
        exit 1
    fi
}

# Install dependencies
function install_deps() {
    DISTRIB_ID=${ID}
    echo ${DEPS_UBUNTU[@]} | xargs sudo ${apt_get} install -y --allow-unauthenticated --no-install-recommends
}

function install_pkgcloud_deps() {
    DISTRIB_ID=${ID}
    echo ${DEPS_UBUNTU_PKGCLOUD[@]} | xargs sudo ${apt_get} install -y --allow-unauthenticated --no-install-recommends
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
    echo ${OP_NAME} > /tmp/${OP_NAME}
}

function setup() {
    echo DISTRIBUTION: ${PRETTY_NAME}
    # export variables depending on the platform we are running
    call_once setup_fdio_repo
    call_once install_deps
    call_once install_pkgcloud_deps
    call_once install_collectd_headers
}

function setup_extras() {
    echo DISTRIBUTION: ${PRETTY_NAME}
    # export variables depending on the platform we are running
    call_once install_deps
    call_once install_collectd_headers
}
