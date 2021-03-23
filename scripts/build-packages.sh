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
    setup

    echo "*******************************************************************"
    echo "********************* STARTING PACKAGE BUILD **********************"
    echo "*******************************************************************"

    # Make the package
    mkdir -p ${SCRIPT_PATH}/../build && pushd ${SCRIPT_PATH}/../build
        rm -rf *

        # First round - Without libmemif
        cmake  -G Ninja -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_APPS=ON ..
        ninja -j8 package

        # Second round - With Libmemif
        rm -rf libtransport ctrl/libhicnctrl
        cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr   \
                       -DBUILD_HICNPLUGIN=ON         \
                       -DBUILD_LIBTRANSPORT=ON       \
                       -DBUILD_APPS=ON               \
                       -DBUILD_HICNLIGHT=OFF         \
                       -DBUILD_SYSREPOPLUGIN=OFF     \
                       -DBUILD_TELEMETRY=ON          \
                       -DBUILD_WSPLUGIN=ON           \
                       ${SCRIPT_PATH}/..

        ninja -j8 package

        find . -not -name '*.deb' -not -name '*.rpm' -print0 | xargs -0 rm -rf -- || true
        rm *Unspecified* || true
    popd

    echo "*******************************************************************"
    echo "*****************  BUILD COMPLETED SUCCESSFULLY *******************"
    echo "*******************************************************************"
}

build_sphinx() {
    setup

    echo "*******************************************************************"
    echo "********************* STARTING DOC BUILD **************************"
    echo "*******************************************************************"

    # Make the package
    pip3 install -r ${SCRIPT_PATH}/../docs/etc/requirements.txt
    pushd ${SCRIPT_PATH}/../docs
    make html

    popd

    echo "*******************************************************************"
    echo "*****************  BUILD COMPLETED SUCCESSFULLY *******************"
    echo "*******************************************************************"
}

build_doxygen() {
    setup

    mkdir -p ${SCRIPT_PATH}/../build-doxygen
    pushd ${SCRIPT_PATH}/../build-doxygen
    cmake -DBUILD_HICNPLUGIN=On -DBUILD_HICNLIGHT=OFF -DBUILD_LIBTRANSPORT=OFF -DBUILD_UTILS=OFF -DBUILD_APPS=OFF -DBUILD_CTRL=OFF ..
    make doc
    popd
}

function usage() {
    echo "Usage: ${0} [sphinx|doxygen|packages]"
    exit 1
}

if [ -z ${1+x} ]; then
    set -- "packages"
fi

case "${1}" in
  sphinx)
    build_sphinx
    ;;
  doxygen)
    build_doxygen
    ;;
  packages)
    build_package
    ;;
  *)
    usage
esac

exit 0
