#!/bin/bash

docker run -d 										\
	   --privileged 								\
	   --cap-add=ALL 							\
	   --security-opt seccomp=unconfined 						\
	   --hostname=vpp-client 							\
	   -e STARTUP_CONF=/home/ubuntu/host-stack/vpp/testbed/startup-client.conf 	\
	   -v /home/ubuntu/host-stack:/home/ubuntu/host-stack				\
	   -v /dev:/dev -v /lib/modules:/lib/modules					\
	   --name vpp-client vpp-develop

docker run -d 										\
	   --privileged 								\
	   --cap-add=SYS_PTRACE 							\
	   --security-opt seccomp=unconfined 						\
	   --hostname=vpp-server							\
	   -e STARTUP_CONF=/home/ubuntu/host-stack/vpp/testbed/startup-server.conf 	\
	   --cap-add=NET_ADMIN 								\
	   -v /home/ubuntu/host-stack:/home/ubuntu/host-stack 				\
	   -v /dev:/dev -v /lib/modules:/lib/modules					\
	   --name vpp-server vpp-develop