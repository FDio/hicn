#!/bin/bash

set -euxo pipefail

export SONAR_HOST_URL=https://sonarcloud.io
export PROJECT_KEY=fdio-hicn
export PROJECT_ORGANIZATION=fdio
export API_TOKEN=9ea26e0b0bbe1f436a0df06d61d1e97dc5a3d6e3

export SONAR_TOKEN=$API_TOKEN
export SONAR_SCANNER_VERSION=4.7.0.2747
export SONAR_SCANNER_HOME=$HOME/.sonar/sonar-scanner-$SONAR_SCANNER_VERSION-linux
curl --create-dirs -sSLo $HOME/.sonar/sonar-scanner.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$SONAR_SCANNER_VERSION-linux.zip
unzip -o $HOME/.sonar/sonar-scanner.zip -d $HOME/.sonar/
export PATH=$SONAR_SCANNER_HOME/bin:$PATH
export SONAR_SCANNER_OPTS="-server"
curl --create-dirs -sSLo $HOME/.sonar/build-wrapper-linux-x86.zip https://sonarcloud.io/static/cpp/build-wrapper-linux-x86.zip
unzip -o $HOME/.sonar/build-wrapper-linux-x86.zip -d $HOME/.sonar/
export PATH=$HOME/.sonar/build-wrapper-linux-x86:$PATH

cd /workspace

git config --global --add safe.directory /workspace
git config --global --add safe.directory /workspace/cmake

rm -rf ${PWD}/build-debug
BUILD_PATH=${PWD}/build-debug
TEST_PATH="${BUILD_PATH}/build-root/bin"

make SONAR_BUILD_WRAPPER=${HOME}/.sonar/build-wrapper-linux-x86/build-wrapper-linux-x86-64 SONAR_OUT_DIR=bw-output BUILD_PATH=${BUILD_PATH} build-coverage

# Run tests to compute test coverage
pushd ${BUILD_PATH}

declare -a TEST_COMPONENTS=(
  "libtransport"
  "lib"
  "hicn_light"
  "hicnplugin"
  "libhicnctrl"
)

# Save first test executable
FIRST_COMPONENT="${TEST_COMPONENTS[0]}"
FIRST_TEST="${TEST_PATH}/${FIRST_COMPONENT}_tests"

# Iterate over all tests: build parameters for next tests and get .profraw data
extension=".profraw"
PROFRAW_FILES=""
REMAINING_TESTS=""
for component in "${TEST_COMPONENTS[@]}"; do
  # Build PROFRAW parameters for next command
  PROFRAW_FILES="${PROFRAW_FILES}${component}${extension} "

  # Save if not first binary
  [[ "${component}" != "${FIRST_COMPONENT}" ]] && REMAINING_TESTS="${REMAINING_TESTS} -object ${TEST_PATH}/${component}_tests"

  # Generate profraw data
  LLVM_PROFILE_FILE="${BUILD_PATH}/${component}${extension}" ${TEST_PATH}/${component}_tests
done

# Merge profraw files
llvm-profdata-11 merge -sparse ${PROFRAW_FILES} -o hicn.profdata

# Generate coverage report
llvm-cov-11 show ${FIRST_TEST} ${REMAINING_TESTS} -instr-profile=hicn.profdata --format=text > ${BUILD_PATH}/coverage.txt

popd

$SONAR_SCANNER_HOME/bin/sonar-scanner \
    -Dsonar.organization=$PROJECT_ORGANIZATION \
    -Dsonar.projectKey=$PROJECT_KEY \
    -Dsonar.sources=/workspace \
    -Dsonar.cfamily.build-wrapper-output=bw-output \
    -Dsonar.host.url=$SONAR_HOST_URL \
    -Dsonar.cfamily.llvm-cov.reportPath=${BUILD_PATH}/coverage.txt
