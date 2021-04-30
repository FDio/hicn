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

#!/bin/bash
set -euxo pipefail

SCRIPT_PATH=$( cd "$(dirname "${BASH_SOURCE}")" ; pwd -P )
source ${SCRIPT_PATH}/functions.sh

# Libparc and libmemif are still not available in Ubuntu 20, so
# we remove it from the list for now.
# TODO Remove it as soon as they are available.
DEPS_UBUNTU=(${DEPS_UBUNTU[@]/"libmemif-dev"})
DEPS_UBUNTU=(${DEPS_UBUNTU[@]/"libmemif"})
DEPS_UBUNTU=(${DEPS_UBUNTU[@]/"libparc-dev"})

DEPS_CENTOS=(${DEPS_CENTOS[@]/"libmemif-devel"})
DEPS_CENTOS=(${DEPS_CENTOS[@]/"libmemif"})
DEPS_CENTOS=(${DEPS_CENTOS[@]/"libparc-devel"})


# Parameters:
# $1 = Package name
#
function build_package() {
    setup

    echo "**************************************************************************"
    echo "********************* STARTING PACKAGE EXTRAS BUILD **********************"
    echo "**************************************************************************"

    mkdir -p build && pushd build
        rm -rf *
        cmake -G Ninja  -DCMAKE_INSTALL_PREFIX=/usr   \
                        -DBUILD_LIBHICN=OFF           \
                        -DBUILD_UTILS=OFF             \
                        -DBUILD_HICNPLUGIN=OFF        \
                        -DBUILD_HICNLIGHT=OFF         \
                        -DBUILD_LIBTRANSPORT=OFF      \
                        -DBUILD_APPS=OFF              \
                        -DBUILD_CTRL=OFF              \
                        -DBUILD_SYSREPOPLUGIN=OFF     \
                        -DBUILD_EXTRAS=ON             \
                        ${SCRIPT_PATH}/..
        ninja

        find . -type f '(' -name '*.deb' -o -name '*.rpm' ')' -exec mv {} . \;
        find . -not -name '*.deb' -not -name '*.rpm' -print0 | xargs -0 rm -rf -- || true
        rm *Unspecified* || true
    popd

    echo "*******************************************************************"
    echo "*****************  BUILD COMPLETED SUCCESSFULLY *******************"
    echo "*******************************************************************"
}

build_package

exit 0
