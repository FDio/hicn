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
VPP_VERSION_DEB=$(git describe --long --match "v*" | sed -E ${VERSION_REGEX})
VPP_VERSION_RPM="${VPP_VERSION_DEB}.x86_64"

DEPS_UBUNTU=("build-essential"
             "doxygen"
             "curl"
             "libparc-dev"
             "libmemif-dev"
             "libmemif"
             "libasio-dev"
             "libconfig-dev"
             "libcurl4-openssl-dev"
             "libevent-dev"
             "libssl-dev"
             "ninja-build"
             "vpp=${VPP_VERSION_DEB}"
             "vpp-dev=${VPP_VERSION_DEB}"
             "libvppinfra=${VPP_VERSION_DEB}"
             "libvppinfra-dev=${VPP_VERSION_DEB}"
             "vpp-plugin-core=${VPP_VERSION_DEB}"
             "python3-ply")

# BUILD_TOOLS_GROUP_CENTOS="'Development Tools'"
DEPS_CENTOS=("vpp-devel-${VPP_VERSION_RPM}"
             "vpp-lib-${VPP_VERSION_RPM}"
             "libparc-devel"
             "curl"
             "libmemif-devel"
             "ninja-build"
             "libmemif"
             "libcurl-devel"
             "asio-devel"
             "libconfig-devel"
             "dnf-plugins-core"
             "bzip2"
             "rpm-build")

COLLECTD_SOURCE="https://github.com/collectd/collectd/releases/download/collectd-5.12.0/collectd-5.12.0.tar.bz2"

function install_collectd_headers() {
    curl -OL ${COLLECTD_SOURCE}
    tar -xf collectd-5.12.0.tar.bz2

    pushd collectd-5.12.0
        ./configure && make -j$(nproc)
    popd

    export COLLECTD_HOME=${PWD}/collectd-5.12.0/src
}

function install_cmake() {
    [[ $(uname --hardware-platform) = "x86_64" ]] || return 0
    CMAKE_INSTALL_SCRIPT_URL="https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-Linux-x86_64.sh"
    CMAKE_INSTALL_SCRIPT="/tmp/install_cmake.sh"
    curl -L ${CMAKE_INSTALL_SCRIPT_URL} > ${CMAKE_INSTALL_SCRIPT}

    sudo mkdir -p ${CMAKE_INSTALL_DIR}
    sudo bash ${CMAKE_INSTALL_SCRIPT} --skip-license --prefix=${CMAKE_INSTALL_DIR}
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

    if [ ${DISTRIB_ID} == "ubuntu" ]; then
        echo ${DEPS_UBUNTU[@]} | xargs sudo ${apt_get} install -y --allow-unauthenticated --no-install-recommends
    elif [ ${DISTRIB_ID} == "centos" ]; then
        yum config-manager --set-enabled powertools
        # Temporary workaround until centos fixes the asio-devel package (https://forums.centos.org/viewtopic.php?t=73034)
        curl -L http://mirror.centos.org/centos/8/PowerTools/x86_64/os/Packages/asio-devel-1.10.8-7.module_el8.1.0+217+4d875839.x86_64.rpm > /tmp/asio-devel-1.10.8-7.module_el8.1.0+217+4d875839.x86_64.rpm
        yum localinstall -y --nogpgcheck /tmp/asio-devel-1.10.8-7.module_el8.1.0+217+4d875839.x86_64.rpm
        echo ${DEPS_CENTOS[@]} | xargs sudo yum install -y --nogpgcheck
    fi
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
    call_once install_cmake
    call_once install_collectd_headers
}
