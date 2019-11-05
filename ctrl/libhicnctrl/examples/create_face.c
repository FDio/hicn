/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file examples/create_face.c
 * \brief libhicnctrl sample code : IPV4/UDP face creation
 *
 * NOTES:
 *  - This sample code is IPv4 only
 */

#include <stdlib.h>
#include <sys/types.h> // getifaddrs
#include <ifaddrs.h> // getifaddrs
#include <stdio.h>
#include <string.h> /* for strncpy */
#include <sys/socket.h> // socket
#include <sys/ioctl.h> // ioctl
#include <unistd.h>

#include <hicn/ctrl.h>
#include <hicn/util/log.h>

int get_local_info(char * if_name, ip_address_t * local_ip) {
    struct ifaddrs *addrs;
    struct ifreq ifr = {
        .ifr_addr.sa_family = AF_INET,
    };
    int ret = -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    getifaddrs(&addrs);

    for (struct ifaddrs * tmp = addrs; tmp; tmp = tmp->ifa_next) {
        if (!tmp->ifa_addr || tmp->ifa_addr->sa_family != AF_PACKET)
            continue;
        if (strcmp(tmp->ifa_name, "lo") == 0)
            continue;
        snprintf(if_name, IFNAMSIZ, "%s", tmp->ifa_name);

        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tmp->ifa_name);
        if (ioctl(fd, SIOCGIFADDR, &ifr) == 1) {
            perror("ioctl");
            continue;
        }

        local_ip->v4.as_inaddr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

        ret = 0;
        break;
    }

    freeifaddrs(addrs);
    close(fd);
    return ret;
}

int main() {
    char remote_ip_str[INET_ADDRSTRLEN] = "1.1.1.1";

    ip_address_t local_ip;
    ip_address_t remote_ip;
    char if_name[IFNAMSIZ];

    /* Retrieving local info */

    if (get_local_info(if_name, &local_ip) < 0) {
        DEBUG("Error getting local information");
        return -1;
    }

    char local_ip_str[MAXSZ_IP_ADDRESS];
    ip_address_snprintf(local_ip_str, MAXSZ_IP_ADDRESS, &local_ip, AF_INET);
    DEBUG("Local information :");
    DEBUG("  - Interface name : %s", if_name);
    DEBUG("  - IP address     : %s", local_ip_str);

    if (ip_address_pton (remote_ip_str, &remote_ip) < 0){
        DEBUG("Error parsing remote IP address");
        return -1;
    }

    /* Filling face information */
    hc_face_t face = {
        .face = {
            .type = FACE_TYPE_UDP,
            .local_addr = local_ip,
            .remote_addr = remote_ip,
            .local_port = 6000,
            .remote_port = 6000,
        },
    };
    if (netdevice_set_name(&face.face.netdevice, if_name) < 0) {
        DEBUG("Error setting face netdevice name");
        return -1;
    }

    /* Connecting to socket and creating face */

    hc_sock_t * socket = hc_sock_create();
    if (!socket){
        DEBUG("Error creating libhicnctrl socket");
        return -1;
    }

    if (hc_sock_connect(socket) < 0){
        DEBUG("Error connecting to forwarder");
        return -1;
    }

    if (hc_face_create(socket, &face) < 0){
        DEBUG("Error creating face");
        return -1;
    }

    DEBUG("Face created successfully");

    hc_sock_free(socket);

    return 0;
}
