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
 * \file interfaces/netlink/netlink.c
 * \brief Netlink interface
 */

#include <linux/rtnetlink.h>
#include <sys/types.h> // getpid
#include <unistd.h> // getpid

#include "../../event.h"
#include "../../facemgr.h"
#include "../../interface.h"

/* Internal data storage */
typedef struct {
    int fd;
} nl_data_t;

// little helper to parsing message using netlink macroses
void parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {  // while not end of the message
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta; // read attr
        }
        rta = RTA_NEXT(rta,len);    // get next attr
    }
}


int nl_initialize(interface_t * interface, face_rules_t * rules, void ** pdata)
{
    nl_data_t * data = malloc(sizeof(nl_data_t));
    if (!data)
        goto ERR_MALLOC;

    data->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (data->fd < 0) {
        printf("Failed to create netlink socket: %s\n", (char*)strerror(errno));
        goto ERR_SOCKET;
    }

    struct sockaddr_nl  local;  // local addr struct
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;       // set protocol family
    local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;   // set groups we interested in
    local.nl_pid = getpid();    // set out id using current process id


    if (bind(data->fd, (struct sockaddr*)&local, sizeof(local)) < 0) {     // bind socket
        printf("Failed to bind netlink socket: %s\n", (char*)strerror(errno));
        goto ERR_BIND;
    }

    /* Issue a first query to receive static state */


    *pdata = data;
    return data->fd; // FACEMGR_SUCCESS;

ERR_BIND:
    close(data->fd);
ERR_SOCKET:
    free(data);
ERR_MALLOC:
    *pdata = NULL;
    return FACEMGR_FAILURE;
}

int nl_callback(interface_t * interface)
{
    nl_data_t * data = (nl_data_t*)interface->data;

    struct sockaddr_nl  local;  // local addr struct
    memset(&local, 0, sizeof(local));

    char buf[8192];             // message buffer
    struct iovec iov;           // message structure
    iov.iov_base = buf;         // set message buffer as io
    iov.iov_len = sizeof(buf);  // set size

    // initialize protocol message header
    struct msghdr msg;
    {
        msg.msg_name = &local;                  // local address
        msg.msg_namelen = sizeof(local);        // address size
        msg.msg_iov = &iov;                     // io vector
        msg.msg_iovlen = 1;                     // io size
    }

    ssize_t status = recvmsg(data->fd, &msg, 0);

    //  check status
    if (status < 0) {
/*
        if (errno == EINTR || errno == EAGAIN)
            continue;
*/

        printf("Failed to read netlink: %s", (char*)strerror(errno));
        return FACEMGR_FAILURE;
    }

    if (msg.msg_namelen != sizeof(local)) { // check message length, just in case
        printf("Invalid length of the sender address struct\n");
        return FACEMGR_FAILURE;
    }

    // message parser
    struct nlmsghdr *h;

    for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); ) {   // read all messagess headers
        int len = h->nlmsg_len;
        int l = len - sizeof(*h);
        char *ifName = NULL;

        if ((l < 0) || (len > status)) {
            printf("Invalid message length: %i\n", len);
            continue;
        }

        // now we can check message type
        if ((h->nlmsg_type == RTM_NEWROUTE) || (h->nlmsg_type == RTM_DELROUTE)) { // some changes in routing table
            printf("Routing table was changed\n");
        } else {    // in other case we need to go deeper
            char *ifUpp;
            char *ifRunn;
            struct ifinfomsg *ifi;  // structure for network interface info
            struct rtattr *tb[IFLA_MAX + 1];

            ifi = (struct ifinfomsg*) NLMSG_DATA(h);    // get information about changed network interface

            parseRtattr(tb, IFLA_MAX, IFLA_RTA(ifi), h->nlmsg_len);  // get attributes

            if (tb[IFLA_IFNAME]) {  // validation
                ifName = (char*)RTA_DATA(tb[IFLA_IFNAME]); // get network interface name
            }

            if (ifi->ifi_flags & IFF_UP) { // get UP flag of the network interface
                ifUpp = (char*)"UP";
            } else {
                ifUpp = (char*)"DOWN";
            }

            if (ifi->ifi_flags & IFF_RUNNING) { // get RUNNING flag of the network interface
                ifRunn = (char*)"RUNNING";
            } else {
                ifRunn = (char*)"NOT RUNNING";
            }

            char ifAddress[256] = {0};    // network addr
            struct ifaddrmsg *ifa; // structure for network interface data
            struct rtattr *tba[IFA_MAX+1];

            ifa = (struct ifaddrmsg*)NLMSG_DATA(h); // get data from the network interface

            parseRtattr(tba, IFA_MAX, IFA_RTA(ifa), h->nlmsg_len);

            if (tba[IFA_LOCAL]) {
                inet_ntop(AF_INET, RTA_DATA(tba[IFA_LOCAL]), ifAddress, sizeof(ifAddress)); // get IP addr
            }

            face_t * face;

            if (tba[IFA_LOCAL]) {
                ip_address_t local_addr = IP_ADDRESS_EMPTY;
                switch(ifa->ifa_family) {
                    case AF_INET:
                        local_addr.v4.as_inaddr = *(struct in_addr*)RTA_DATA(tba[IFA_LOCAL]);
                        break;
                    case AF_INET6:
                        local_addr.v6.as_in6addr = *(struct in6_addr*)RTA_DATA(tba[IFA_LOCAL]);
                        break;
                    default:
                        continue;
                }
                face = face_create_udp(&local_addr, 0, &IP_ADDRESS_EMPTY, 0, ifa->ifa_family);
            } else {
                face = NULL;
            }

            switch (h->nlmsg_type) {
                case RTM_DELADDR:
                    // DOES NOT SEEM TO BE TRIGGERED
                    printf("Interface %s: address was removed\n", ifName);
                    if (face)
                        event_raise(EVENT_TYPE_DELETE, face, interface);
                    break;

                case RTM_DELLINK:
                    printf("Network interface %s was removed\n", ifName);
                    break;

                case RTM_NEWLINK:
                    printf("New network interface %s, state: %s %s\n", ifName, ifUpp, ifRunn);
                    // UP RUNNING
                    // UP NOT RUNNING
                    // DOWN NOT RUNNING
                    if (!(ifi->ifi_flags & IFF_UP) || (!(ifi->ifi_flags & IFF_RUNNING))) {
                        if(face)
                            event_raise(EVENT_TYPE_DELETE, face, interface);
                    }
                    break;

                case RTM_NEWADDR:
                    printf("Interface %s: new address was assigned: %s\n", ifName, ifAddress);
                    printf("NEW FACE\n");
                    if (face)
                        event_raise(EVENT_TYPE_CREATE, face, interface);
                    break;
            }
        }

        status -= NLMSG_ALIGN(len); // align offsets by the message length, this is important

        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));    // get next message
    }

    return FACEMGR_SUCCESS;
}

int nl_finalize(interface_t * interface)
{
    nl_data_t * data = (nl_data_t*)interface->data;
    close(data->fd);
    return FACEMGR_SUCCESS;

}

const interface_ops_t netlink_ops = {
    .type = "netlink",
    .is_singleton = true,
    .initialize = nl_initialize,
    .callback = nl_callback,
    .finalize = nl_finalize,
    .on_event = NULL,
};
