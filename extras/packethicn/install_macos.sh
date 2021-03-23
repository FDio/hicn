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

mkdir -p build
pushd build

cmake .. || exit 1
make || exit 1

echo "Installing..."
sudo make install || exit 1
popd

BUILD_DIR="build/build-root/lib"
SO_LIB="packethicn.so"

WS_LIB_PATH_LIST=$(otool -L $BUILD_DIR/$SO_LIB | grep wireshark | awk '{print $1}')

while IFS= read -r PATHL; do
  LIB=$(echo $PATHL | cut -d / -f 7)
  install_name_tool -change $PATHL @rpath/$LIB $BUILD_DIR/$SO_LIB
done <<< "$WS_LIB_PATH_LIST"

WS_GUI_PATH_LIST=$(find /usr/local -name Wireshark.app -print 2>/dev/null)
if [ $? == 0 ]; then
  while IFS= read -r PATHL; do
    EPAN_PATH=$(find ${PATHL}/Contents -name epan)
    cp $BUILD_DIR/$SO_LIB $EPAN_PATH
    echo "Installed $BUILD_DIR/$SO_LIB in $EPAN_PATH"
  done <<< "$WS_GUI_PATH_LIST"
else
  echo "Can't find the Wireshark GUI. Please copy $BUILD_DIR/$SO_LIB into the Wireshark plugin folder"
fi
