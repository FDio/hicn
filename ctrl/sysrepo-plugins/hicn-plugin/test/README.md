# test hICN sysrepo plugin

Two simple tests are provided to verify the functionality of the plugin. In ```netconf-test``` you can find ```test.py``` which uses netconf-clinet library to send NETCONF command toward the sysrepo. This is the usage:
```
python test.py host user password operation
```
<b>host</b> indicates the host information. <b>user</b>, <b>password</b> are credentials to connect to the device. <b>Operation</b> can be one of the following:
```
- route_dump
   It receives the route operational data from vpp
- face_dump
   It receives the face operational data from vpp
- face_add
   It adds an hICN face in the vpp
- punt_add
   It adds a punt in the vpp
- route_add
  It adds route in the vpp
- face_dell
  It deletes  face from vpp
- route_del
  It deletes route from vpp
- punt_del
  It deletes punt from vpp
```

In the ```vapi-test``` you can find testing the VAPI for  the communication between the hICN sysrepo plugin and vpp. This is the usage:

```
./test [route_add [4|6], punt_add [4|6], face_add [4|6], route_dump, face_dump]
```
The definition for the argument is the same as the netconf-test except that here you can choose the test for IPV4 and IPV6.
