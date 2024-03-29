# Copyright (c) 2017-2022 Cisco and/or its affiliates.
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

BUILD_PATH="${SCRIPT_PATH}/../packages"
TEST_REPORT_DIR="${BUILD_PATH}/reports"
BUILD_ROOT_DIR="${BUILD_PATH}/build-root/bin"
MAKE_FOLDER="${SCRIPT_PATH}/.."

function execute_tests() {
    mkdir -p "${TEST_REPORT_DIR}"
    pushd "${BUILD_ROOT_DIR}"
      for component in "${TEST_COMPONENTS[@]}"; do
        GTEST_OUTPUT="xml:${TEST_REPORT_DIR}/${component}-report.xml" "./${component}_tests"
      done
    popd
}

# Parameters:
# $1 = Package name
#
function build_package() {
    setup

    echo "*******************************************************************"
    echo "********************* STARTING PACKAGE BUILD **********************"
    echo "*******************************************************************"

    # Run unit tests and make the package
    make -C "${MAKE_FOLDER}" BUILD_PATH="${BUILD_PATH}" INSTALL_PREFIX=/usr package-release

    execute_tests

    pushd "${BUILD_PATH}"
      find . -not -name '*.deb' \
        -not -name '*.rpm' \
        -not -name 'reports' \
        -not -name '*report.xml' \
        -print0 | xargs -0 rm -rf -- || true
      rm ./*Unspecified* ./*Development* ./*development* || true
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

    make doc

    echo "*******************************************************************"
    echo "*****************  BUILD COMPLETED SUCCESSFULLY *******************"
    echo "*******************************************************************"
}

function usage() {
    echo "Usage: ${0} [sphinx|packages]"
    exit 1
}

if [ -z ${1+x} ]; then
    set -- "packages"
fi

case "${1}" in
  sphinx)
    build_sphinx
    ;;
  packages)
    build_package
    ;;
  vpp_master)
    ;;
  *)
    usage
    exit 1
esac

exit 0
