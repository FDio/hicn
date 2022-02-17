# Copyright (c) 2022 Cisco and/or its affiliates.
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

SCRIPT_PATH=$( cd "$(dirname "${BASH_SOURCE}")" ; pwd -P )
source ${SCRIPT_PATH}/functions.sh

function clean_fdio_apt_sources_lists() {
    sudo rm -f /etc/apt/sources.list.d/fdio_*.list
}

function setup_vpp_master() {
    call_once install_deps

    # Install libparc & libmemif from fdio/release
    export DEPS_UBUNTU_PKGCLOUD=("libparc-dev"
                                "libmemif-dev"
                                "libmemif"
                                )
    clean_fdio_apt_sources_lists
    setup_fdio_repo
    install_pkgcloud_deps

    # Install vpp pkgs from fdio/master
    export PACKAGECLOUD_RELEASE_REPO_DEB="https://packagecloud.io/install/repositories/fdio/master/script.deb.sh"
    export DEPS_UBUNTU_PKGCLOUD=("vpp"
                                "vpp-dev"
                                "libvppinfra"
                                "libvppinfra-dev"
                                "vpp-plugin-core"
                                )
    clean_fdio_apt_sources_lists
    setup_fdio_repo
    install_pkgcloud_deps

    call_once install_collectd_headers
}

# Parameters:
# $1 = Package name
#
function build_package() {
    setup_vpp_master

    echo "*******************************************************************"
    echo "********************* STARTING PACKAGE BUILD **********************"
    echo "*******************************************************************"

    # Make the package
    mkdir -p ${SCRIPT_PATH}/../build && pushd ${SCRIPT_PATH}/../build
        rm -rf *

        cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr    \
                       -DBUILD_HICNPLUGIN=ON          \
                       -DBUILD_LIBTRANSPORT=ON        \
                       -DBUILD_APPS=ON                \
                       -DBUILD_HICNLIGHT=ON           \
                       -DBUILD_TELEMETRY=ON           \
                       ${SCRIPT_PATH}/..

        ninja -j8 package

        find . -not -name '*.deb' -print0 | xargs -0 rm -rf -- || true
        rm -f *Unspecified* *Development* *development*
    popd

    echo "*******************************************************************"
    echo "*****************  BUILD COMPLETED SUCCESSFULLY *******************"
    echo "*******************************************************************"
}

build_package

exit 0
