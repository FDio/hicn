#!/usr/bin/env bash
set -xue

SCRIPT_PATH=$( cd "$(dirname "${BASH_SOURCE}")" ; pwd -P )

pushd ${SCRIPT_PATH}
find src/ -type f '(' -name '*.c' -o -name '*.cc' -o -name '*.h' ')' -exec clang-format -style=file -i {} \;
popd