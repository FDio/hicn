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


# Parameters:
# $1 = Package name
#
function build_package() {
    setup_extras

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

        find . -type f -name '*.deb' -exec mv {} . \;
        find . -not -name '*.deb' -print0 | xargs -0 rm -rf -- || true
        rm *Unspecified* || true
    popd

    echo "*******************************************************************"
    echo "*****************  BUILD COMPLETED SUCCESSFULLY *******************"
    echo "*******************************************************************"
}

build_package

exit 0
