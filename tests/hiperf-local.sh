#!/usr/bin/env bash
set -eo pipefail

if [[ "$(basename $(pwd))" != build* ]]; then
  echo "Error: launch script from build dir"
  exit 1
fi

# Stop forwarder and hiperf if already running
sudo killall -9 hicn-light-daemon hiperf 2>/dev/null || true

# Start forwarder and hiperf server in background
ninja && sudo ./build-root/bin/hicn-light-daemon --daemon --log-file /tmp/lite_client.log >/dev/null
./build-root/bin/hiperf -z hicnlightng_module -S b001::/16 &

# Run hiperf client for 20 seconds
sleep 1
./build-root/bin/hiperf -z hicnlightng_module -C b001:: -W 50 -n 20

# Clean up
sudo killall -9 hicn-light-daemon hiperf
