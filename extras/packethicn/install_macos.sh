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
