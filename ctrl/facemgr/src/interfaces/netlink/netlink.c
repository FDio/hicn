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

#include <assert.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h> // ARPHRD_LOOPBACK
#include <sys/types.h> // getpid
#include <unistd.h> // getpid

#include <hicn/facemgr.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>

#include "../../common.h"
#include "../../interface.h"

typedef enum {
    NL_STATE_UNDEFINED,
    NL_STATE_LINK_SENT,
    NL_STATE_ADDR_SENT,
    NL_STATE_DONE,
} nl_state_t;

/* Internal data storage */
typedef struct {
    int fd;
    nl_state_t state;
} nl_data_t;

static inline void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len,
	unsigned short flags)
{
    unsigned short type;

    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        type = rta->rta_type & ~flags;
        if (type <= max)
            tb[type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

int nl_process_state(interface_t * interface)
{
    nl_data_t * data = (nl_data_t*)interface->data;
    int rc;

    switch(data->state) {
        case NL_STATE_UNDEFINED:
        {
            DEBUG("[nl_process_state] UNDEFINED->LINK_SENT");
            struct {
                struct nlmsghdr  header;
                struct rtgenmsg payload;
            } msg2 = {
                .header = {
                    .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)),
                    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                    .nlmsg_type = RTM_GETLINK,
                    .nlmsg_pid = getpid(),
                    .nlmsg_seq = 3,
                },
                .payload = {
                    .rtgen_family = AF_PACKET,
                }
            };

            rc = send(data->fd, &msg2, msg2.header.nlmsg_len, 0);
            if (rc < 0)
                printf("E: Error sending netlink query\n");

            data->state = NL_STATE_LINK_SENT;
            break;
        }

        case NL_STATE_LINK_SENT:
        {
            DEBUG("[nl_process_state] LINK_SENT->ADDR_SENT");
            /* Issue a first query to receive static state */
            struct {
                struct nlmsghdr  header;
                struct ifaddrmsg payload;
            } msg = {
                .header = {
                    .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                    .nlmsg_type = RTM_GETADDR,
                    .nlmsg_pid = getpid(),
                    .nlmsg_seq = 7,
                },
                .payload = {
                    .ifa_family = AF_INET,
                }
            };

            rc = send(data->fd, &msg, msg.header.nlmsg_len, 0);
            if (rc < 0)
                printf("E: Error sending netlink query\n");

            data->state = NL_STATE_ADDR_SENT;
            break;
        }

        case NL_STATE_ADDR_SENT:
        {
            DEBUG("[nl_process_state] ADDR_SENT->DONE");
            data->state = NL_STATE_DONE;
            break;
        }

        default: /* NL_STATE_DONE never called */
            break;
    }

    return 0;
}

int nl_initialize(interface_t * interface, void * cfg)
{
    nl_data_t * data = malloc(sizeof(nl_data_t));
    if (!data)
        goto ERR_MALLOC;

    data->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (data->fd < 0) {
        ERROR("[nl_initialize] Failed to create netlink socket: %s", (char*)strerror(errno));
        goto ERR_SOCKET;
    }

    data->state = NL_STATE_UNDEFINED;

    struct sockaddr_nl  local;  // local addr struct
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;       // set protocol family
    // NOTE: RTNLGRP_LINK replaces obsolete RTMGRP_LINK, etc
    local.nl_groups = 0
        | RTMGRP_LINK
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV6_IFADDR
#if 0
        | RTMGRP_IPV4_ROUTE;
        | RTMGRP_IPV6_ROUTE;
#endif
        ;
    local.nl_pid = getpid();    // set out id using current process id

    if (bind(data->fd, (struct sockaddr*)&local, sizeof(local)) < 0) {     // bind socket
        ERROR("[nl_initialize] Failed to bind netlink socket: %s", (char*)strerror(errno));
        goto ERR_BIND;
    }

    interface->data = data;

    if (interface_register_fd(interface, data->fd, NULL) < 0) {
        ERROR("[nl_initialize] Error registering fd");
        goto ERR_FD;
    }

#if 1
    nl_process_state(interface);
#endif

    return 0;

ERR_FD:
ERR_BIND:
    close(data->fd);
ERR_SOCKET:
    free(data);
ERR_MALLOC:
    return -1;
}

int parse_link(struct nlmsghdr * h, facelet_t ** facelet,
        char * interface_name, size_t interface_name_size,
        bool * up, bool * running)
{
    struct ifinfomsg *ifi;  // structure for network interface info
    struct rtattr *tb[IFLA_MAX + 1];

    assert(facelet);

    ifi = (struct ifinfomsg*) NLMSG_DATA(h);    // get information about changed network interface
    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(h), 1<<15);

    if (interface_name) {
        assert(tb[IFLA_IFNAME]);
        snprintf(interface_name, interface_name_size, "%s", (char*)RTA_DATA(tb[IFLA_IFNAME]));
    }

    if (up)
        *up = ifi->ifi_flags & IFF_UP;
    if (running)
        *running = ifi->ifi_flags & IFF_RUNNING;


    netdevice_t * netdevice = netdevice_create_from_name(interface_name);
    if (!netdevice) {
        ERROR("[netlink.parse_link] error creating netdevice '%s'", interface_name);
        goto ERR_ND;
    }

    *facelet = facelet_create();
    if (!*facelet) {
        ERROR("[netlink.parse_link] error creating facelet");
        goto ERR_FACELET;
    }

    if (facelet_set_netdevice(*facelet, *netdevice) < 0) {
        ERROR("[netlink.parse_link] error setting netdevice");
        goto ERR;
    }

// FIXME Tags
#if 0
    /* This is the only opportunity to identify a loopback interface on both
     * linux _and_ android, as NetworkCapabilities does not have a flag for
     * LOOPBACK... */
    if (ifi->ifi_type==ARPHRD_LOOPBACK) {
        DEBUG("loopback");
    }

#ifdef IFLA_WIRELESS
    /*
     * This signals a wirless event, but it typically occurs _after_ a face is
     * created... we might need to update an existing face by setting a tag...
     * or find a way to exploit this flag before actually creating the face...
     */
    if (tb[IFLA_WIRELESS])
        DEBUG("wireless!!!");
#else
#warning "IFLA_WIRELESS not supported on this platform"
#endif /* IFLA_WIRELESS */

#endif

    // TODO
    //  - ifi_change
    //  - IFLA_PROTINFO

    netdevice_free(netdevice);
    return 0;

ERR:
    facelet_free(*facelet);
    *facelet = NULL;
ERR_FACELET:
    netdevice_free(netdevice);
ERR_ND:
    return -1;
}

int parse_addr(struct nlmsghdr * h, facelet_t ** facelet,
        char * interface_name, size_t interface_name_size,
        char * interface_address, size_t interface_address_size)
{
    ip_address_t local_addr = IP_ADDRESS_EMPTY;
    struct ifaddrmsg *ifa; // structure for network interface data
    struct rtattr *tba[IFA_MAX+1];

    assert(facelet);

    ifa = (struct ifaddrmsg*)NLMSG_DATA(h); // get data from the network interface

    parse_rtattr(tba, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(h), 0);

    /* FIXME
     *
     * IFA_LOCAL ok for v4, not there for v6
     *
     * IFA_ADDRESS seems to work for both but with the following precaution
     *
     * IFA_ADDRESS is prefix address, rather than local interface address.
     * It makes no difference for normally configured broadcast interfaces,
     * but for point-to-point IFA_ADDRESS is DESTINATION address,
     * local address is supplied in IFA_LOCAL attribute.
     */
    if (!tba[IFA_ADDRESS]) {
        ERROR("[netlink.parse_addr] No local address");
        return -1;
    }

    switch(ifa->ifa_family) {
        case AF_INET:
            local_addr.v4.as_inaddr = *(struct in_addr*)RTA_DATA(tba[IFA_ADDRESS]);
            break;
        case AF_INET6:
            local_addr.v6.as_in6addr = *(struct in6_addr*)RTA_DATA(tba[IFA_ADDRESS]);
            break;
        default:
            return 0;
    }

    /* See comment in parse_link */
    if (interface_address) {
        assert(tba[IFA_ADDRESS]);
        ip_address_snprintf(interface_address, interface_address_size, &local_addr, ifa->ifa_family);
    }

    netdevice_t * netdevice = netdevice_create_from_index(ifa->ifa_index);
    if (!netdevice) {
        ERROR("[netlink.parse_addr] error creating netdevice from index '%d'", ifa->ifa_index);
        goto ERR_ND;
    }

    if (interface_name) {
        snprintf(interface_name, interface_name_size, "%s", netdevice->name);
    }

    *facelet = facelet_create();
    if (!*facelet) {
        ERROR("[netlink.parse_addr] error creating facelet");
        goto ERR_FACELET;
    }
    if (facelet_set_netdevice(*facelet, *netdevice) < 0) {
        ERROR("[netlink.parse_addr] error setting netdevice");
        goto ERR;
    }
    if (facelet_set_family(*facelet, ifa->ifa_family) < 0) {
        ERROR("[netlink.parse_addr] error setting family");
        goto ERR;
    }
    if (facelet_set_local_addr(*facelet, local_addr) < 0) {
        ERROR("[netlink.parse_addr] error setting local address");
        goto ERR;
    }

    netdevice_free(netdevice);
    return 0;

ERR:
    facelet_free(*facelet);
    *facelet = NULL;
ERR_FACELET:
    netdevice_free(netdevice);
ERR_ND:
    return -1;
}

int nl_callback(interface_t * interface, int fd, void * unused)
{
    nl_data_t * data = (nl_data_t*)interface->data;

    struct sockaddr_nl  local;  // local addr struct
    memset(&local, 0, sizeof(local));

    char buf[8192];             // message buffer
    struct iovec iov;           // message structure
    iov.iov_base = buf;         // set message buffer as io
    iov.iov_len = sizeof(buf);  // set size

    // initialize protocol message header
    struct msghdr msg = {
        .msg_name = &local,                  // local address
        .msg_namelen = sizeof(local),        // address size
        .msg_iov = &iov,                     // io vector
        .msg_iovlen = 1,                     // io size
    };

    ssize_t status = recvmsg(data->fd, &msg, 0);

    //  check status
    if (status < 0) {
/*
        if (errno == EINTR || errno == EAGAIN)
            continue;
*/

        printf("Failed to read netlink: %s", (char*)strerror(errno));
        return -1;
    }

    if (msg.msg_namelen != sizeof(local)) { // check message length, just in case
        printf("Invalid length of the sender address struct\n");
        return -1;
    }

    // message parser
    struct nlmsghdr *h;

    for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); ) {   // read all messagess headers
        int len = h->nlmsg_len;
        int l = len - sizeof(*h);

        if ((l < 0) || (len > status)) {
            printf("Invalid message length: %i\n", len);
            continue;
        }

        switch(h->nlmsg_type) {
#if 0
            case RTM_NEWROUTE:
            case RTM_DELROUTE:
                DEBUG("Routing table was changed");
                break;
#endif

            case RTM_DELADDR:
            {
                facelet_t * facelet = NULL;
                char interface_name[IFNAMSIZ];
                char interface_address[MAXSZ_IP_ADDRESS] = {0};

                if (parse_addr(h, &facelet, interface_name, IFNAMSIZ,
                            interface_address, MAXSZ_IP_ADDRESS) < 0) {
                    ERROR("Error parsing address message");
                    break;
                }

                DEBUG("[NETLINK] Interface %s: address was removed", interface_name);
                if (facelet) {
                    facelet_set_event(facelet, FACELET_EVENT_SET_DOWN);
                    facelet_set_attr_clean(facelet);
                    interface_raise_event(interface, facelet);
                }
                break;
            }

            case RTM_NEWADDR:
            {
                facelet_t * facelet = NULL;
                char interface_name[IFNAMSIZ];
                char interface_address[MAXSZ_IP_ADDRESS] = {0};

                if (parse_addr(h, &facelet, interface_name, IFNAMSIZ,
                            interface_address, MAXSZ_IP_ADDRESS) < 0) {
                    ERROR("Error parsing address message");
                    break;
                }

                DEBUG("[NETLINK] Interface %s: new address was assigned: %s", interface_name, interface_address);

                if (facelet) {
                    facelet_set_event(facelet, FACELET_EVENT_UPDATE);
                    facelet_set_attr_clean(facelet);
                    interface_raise_event(interface, facelet);
                }
                break;
            }

            case RTM_DELLINK:
            {
                /* This does not always seem to be called, hence we rely on
                 * down, not running */
                facelet_t * facelet = NULL;
                char interface_name[IFNAMSIZ];
                if (parse_link(h, &facelet, interface_name, IFNAMSIZ,
                            NULL, NULL) < 0) {
                    ERROR("Error parsing link message");
                    break;
                }

                DEBUG("[NETLINK] Network interface %s was removed", interface_name);

                if (!facelet)
                    break;

                facelet_set_event(facelet, FACELET_EVENT_DELETE);
                facelet_set_attr_clean(facelet);
                interface_raise_event(interface, facelet);

                break;
            }

            case RTM_NEWLINK:
            {
                facelet_t * facelet = NULL;
                char interface_name[IFNAMSIZ];
                bool up, running;

                if (parse_link(h, &facelet, interface_name, IFNAMSIZ, &up, &running) < 0) {
                    ERROR("Error parsing link message");
                    break;
                }

                // UP RUNNING
                // UP NOT RUNNING
                // DOWN NOT RUNNING
#if 1
                DEBUG("[NETLINK] New network interface %s, state: %s %s", interface_name,
                        up ? "UP" : "DOWN",
                        running ? "RUNNING" : "NOT_RUNNING");
#endif

                if (!facelet)
                    break;
                if (up && running) {
                    facelet_set_event(facelet, FACELET_EVENT_CREATE);
                    //facelet_set_family(facelet, AF_INET);
                    facelet_set_attr_clean(facelet);
                    interface_raise_event(interface, facelet);

#if 0
                    facelet_t * facelet6 = facelet_dup(facelet);
                    if (!facelet6) {
                        ERROR("Could not duplicate face for v6");
                        break;
                    }
                    facelet_set_family(facelet6, AF_INET6);
                    interface_raise_event(interface, facelet6);
#endif
//                } else {
//#if 1
//                    facelet_set_event(facelet, FACELET_EVENT_SET_DOWN);
//                    facelet_set_attr_clean(facelet);
//                    interface_raise_event(interface, facelet);
//#else
//                    facelet_free(facelet);
//#endif
                }
                break;
            }

            case NLMSG_ERROR:
                break;
            case NLMSG_DONE:
                nl_process_state(interface);
                break;
            default:
                break;

        }

        status -= NLMSG_ALIGN(len); // align offsets by the message length, this is important

        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));    // get next message
    }

    return 0;
}

int nl_finalize(interface_t * interface)
{
    nl_data_t * data = (nl_data_t*)interface->data;
    close(data->fd);
    free(interface->data);
    return 0;

}

const interface_ops_t netlink_ops = {
    .type = "netlink",
    .initialize = nl_initialize,
    .callback = nl_callback,
    .finalize = nl_finalize,
    .on_event = NULL,
};
