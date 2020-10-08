#!/bin/bash

sudo modprobe uio_pci_generic
sudo cp /home/ubuntu/host-stack/install/lib/libhicn.so /usr/lib/libhicn.so

tail -f /dev/null