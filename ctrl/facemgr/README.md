# hICN Face Manager

The bonjour interfaces uses SO_BINDTODEVICE to be able to send bonjour queries
to the right interfaces. As such facemgr has to be run as root, or with the
CAP_NET_RAW capability.

```
sudo getcap build-root/bin/facemgr
sudo setcap cap_net_raw+ep build-root/bin/facemgr
sudo getcap build-root/bin/facemgr
```
