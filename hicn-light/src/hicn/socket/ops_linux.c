#include <sys/ioctl.h>   // ioctl
#include <sys/socket.h>  // needed by linux/if.h
#include <errno.h>
#include <fcntl.h>  // ''
#include <linux/if_tun.h>
#include <linux/limits.h>  // PATH_MAX
#include <stdio.h>         // fprintf
#include <string.h>        // memset
#include <sys/stat.h>      // open
#include <sys/uio.h>       // writev
#include <unistd.h>        // close

#include "error.h"
#include "ops.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

/******************************************************************************
 * netlink.h
 ******************************************************************************/

#ifndef HICN_NETLINK_H
#define HICN_NETLINK_H

#include <stdint.h>
#include <stdlib.h>

/* Public interface */

/**
 * Get the interface ID of an interface by its name
 *
 * @return 32-bit interface identifier in case of success, or 0.
 *
 * @see if_nametoindex
 *
 */
uint32_t _nl_get_ifid(const char *ifname);

/**
 * Retrieve the output interface corresponding to the specified IP address.
 *
 * @param [in] addr IP(v6) address in presentation form.
 * @param [out] Identifier of the corresponding output interface.
 * @return int 0 in case of success, -1 otherwise
 */
int _nl_get_output_ifid(const char *ip_address, uint8_t address_family,
                        uint32_t *interface_id);

/**
 * Retrieve the first IP address of an interface (identified by its id) which
 * has a netmask < 128.
 *
 * @param [in] s File descriptor of the netlink socket (deprecated).
 * @param [in] interface_id Identifier of the interface for which to retrieve
 *      the IP address.
 * @param [out] addr IP(v6) address in binary form.
 * @return int 0 in case of success, -1 otherwise
 *
 * @see getifaddrs
 */
int _nl_get_ip_addr(uint32_t interface_id, uint8_t address_family,
                    ip_prefix_t *ip_address);

int _nl_set_ip_addr(uint32_t interface_id, ip_prefix_t *ip_address);

int _nl_up_if(uint32_t interface_id);

int _nl_add_in_route_table(const ip_prefix_t *prefix,
                           const uint32_t interface_id, const uint8_t table_id);
int _nl_add_in_route_table_s(const char *prefix, const uint32_t interface_id,
                             const uint8_t table_id);
int _nl_add_in_route_s(const char *prefix, const uint32_t interface_id);

int _nl_add_out_route(const char *gateway, const uint8_t address_family,
                      const uint8_t table_idi, int default_route);
int _nl_del_out_route(const char *gateway, const uint8_t address_family,
                      const uint8_t table_id);

int _nl_del_lo_route(const ip_prefix_t *ip_address);

int _nl_add_rule(const char *interface_name, const uint8_t address_family,
                 const uint8_t table_id);
int _nl_del_rule(const char *interface_name, const uint8_t address_family,
                 const uint8_t table_id);

int _nl_add_neigh_proxy(const ip_prefix_t *ip_address,
                        const uint32_t interface_id);

int _nl_add_prio_rule(const ip_prefix_t *ip_address,
                      const uint8_t address_family, const uint32_t priority,
                      const uint8_t table_id);
int _nl_add_lo_prio_rule(const ip_prefix_t *ip_address,
                         const uint8_t address_family, const uint32_t priority);
int _nl_del_prio_rule(const ip_prefix_t *ip_address,
                      const uint8_t address_family, const uint32_t priority,
                      const uint8_t table_id);
int _nl_del_lo_prio_rule(const ip_prefix_t *ip_address,
                         const uint8_t address_family, const uint32_t priority);

#endif /* HICN_NETLINK_H */

/******************************************************************************
 * netlink.c
 ******************************************************************************/

/*
 * This module offers an interface to the Netlink API appropriate for
 * implementing punting as required by hICN (1).
 *
 * More specifically, it consists of the following functionalities:
 *  - LINK
 *     . map interface name to ID
 *     . set and interface up
 *  - ADDR
 *     . get and set ip addresses on a given interface ID
 *  - ROUTE
 *     . get output interface id towards IP (ip route get IP > interface_id)
 *     . add input route (ip route add PREFIX dev INTERFACE) for punting
 *     interests . add output route (ip route add default GATEWAY table TABLE)
 *     for routing interests (2, 3)
 *     . delete local route towards IP (ip route del IP table local)
 *  - RULE
 *     . add output rule (ip rule add iif interface table TABLE) for routing
 *     interests (2, 3) - ND PROXY
 *     . enable NDP proxy functionality for IP on interface ID (ip -6 neigh add
 *     proxy IP dev INTERFACE) for allowing the TUN to be reachable on the
 *     reverse data path
 *
 * Implementation notes:
 *  (1) We have not been using the libnl library because it requires
 *      manipulating too many function and data structures for a simple purpose.
 *      Currently, many parts of the code are somehow repetitive, but this might
 *      be improved by a proper API in a future release.
 *  (2) allows load balancing over different interfaces = multihoming. Please
 *      note that it is not possible to have load balancing over two faces using
 *      the same output interface as we are using the underlying IP network !
 *      This might be mitigated with the use of SR however.
 *  (3) The implementation of punting heavily uses the policy routing
 *      functionalities, as we need to hook through a TUN into user space a
 *      whole prefix used as a destination (for interests) or source (for data
 *      packets). We thus combine the use of rules to assign routing table IDs,
 *      and routes inside those tables. As there is no easy way to allocate
 *      which routing tables we use, we made the choice to index them by the ID
 *      of the interface, assuming there is no external conflict. This might be
 *      improved in the future.
 *
 *      This hICN implementation uses TUNs in two different ways:
 *       - a main TUN interface, which receives all punted interests,
 *       demultiplex them before assigning them an input face (eventually
 *       dynamically creating it);
 *       - a set of output TUN interfaces, aka faces, used for routing of
 *       interests, and for receiving the corresponding data packets on the way
 *       back. Punting of data packets if based of their destination IP, which
 *       is the IP of the physical output interface used for the interest, which
 *       is unique (cf (2)).
 *
 *      The corresponding routing tables IDs are :
 *       MAIN_TUN_ID -> used for punting of data packets
 *       OUTPUT_TUN_ID_i -> used for routing of interests towards next hop
 *       (bypassing local IP routing table)
 *
 *      Note that punting of interests is done just through a route, and routing
 *      of data packets is done just through the regular IP routing table on the
 *      note after the address translation done in the forwarder.
 *
 *   - Forging netlink packets
 *
 *     A previous implementation used function calls with pointers to populate
 *     the various header parts in a buffer in order to build a netlink packet.
 *     A newer implementation uses nested structs and iovecs to build the whole
 *     packet in a single write call. This should allow a simpler evolution
 *     towards a cleaner API.
 */

#include <arpa/inet.h>        // inet_pton
#include <errno.h>            // errno
#include <linux/fib_rules.h>  // fib_rule_hdr, FRA_*
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>      // IFF_UP
#include <netinet/in.h>  // in6addr
#include <stdio.h>       // perror
#include <string.h>
#include <sys/socket.h>  // ''
#include <sys/types.h>   // socket
#include <unistd.h>      // read

#include <sys/socket.h>  // ''
#include <sys/types.h>   // send, recv

#define BUFSIZE 4096
#define FLAGS_CREATE NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK
#define FLAGS_CREATE_MATCH \
  NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_MATCH

#define FLAGS_GET NLM_F_REQUEST
#define FLAGS_GET_ROOT (NLM_F_REQUEST | NLM_F_ROOT)

#define FLAGS_LIST NLM_F_REQUEST | NLM_F_DUMP

#ifndef __ANDROID__
#define IF_NAMESIZE 16
#endif
#define FR_ACT_TO_TBL 1
#define NLMSG_BOTTOM(nlmsg) \
  ((struct rtattr *)(((void *)(nlmsg)) + NLMSG_ALIGN((nlmsg)->nlmsg_len)))

int seq = 1;

static inline size_t iov_length(const struct iovec *iov,
                                unsigned long nr_segs) {
  unsigned long seg;
  size_t ret = 0;

  for (seg = 0; seg < nr_segs; seg++) ret += iov[seg].iov_len;
  return ret;
}

typedef struct {
  struct nlmsghdr hdr;
  struct nlmsgerr payload;
} nl_err_hdr_t;

/* Low level : nl header */

int _nl_get_socket() { return socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE); }

int _nl_header(int request, uint8_t *buffer, size_t len, uint32_t flags) {
  struct nlmsghdr *nl = (struct nlmsghdr *)buffer;

  nl->nlmsg_len = 0;  // NLMSG_LENGTH(sizeof(struct ifinfomsg));
  nl->nlmsg_type = request;
  nl->nlmsg_flags = flags;
  nl->nlmsg_seq = seq++;  //
  nl->nlmsg_pid = 0;      // getpid();

  return 0;
}

/* Low level : nl protocols */

/* Low level : attributes */

int addAttr(struct nlmsghdr *nl, int maxlen, int type, void *data,
            int attr_len) {
  struct rtattr *rta;
  int len = RTA_LENGTH(attr_len);

  if (NLMSG_ALIGN(nl->nlmsg_len) + len > maxlen) {
    exit(EXIT_FAILURE);
  }

  rta = (struct rtattr *)((char *)nl + NLMSG_ALIGN(nl->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy(RTA_DATA(rta), data, attr_len);
  nl->nlmsg_len = NLMSG_ALIGN(nl->nlmsg_len) + len;
  return 0;
}

int _nl_payload_rule(uint8_t table_id, uint8_t address_family, uint8_t *buffer,
                     size_t len) {
  struct nlmsghdr *nl = (struct nlmsghdr *)buffer;
  struct fib_rule_hdr *frh = (struct fib_rule_hdr *)(NLMSG_DATA(buffer));

  memset(frh, 0, sizeof(struct fib_rule_hdr));
  frh->family = address_family;
  frh->table = table_id;
  frh->action = FR_ACT_TO_TBL,
  frh->flags = NLM_F_REPLACE;  // 0
  frh->tos = 0;

  nl->nlmsg_len += NLMSG_LENGTH(sizeof(struct fib_rule_hdr));

  return 0;
}

int _nl_payload_link(uint32_t ifindex, uint8_t *buffer, size_t len) {
  struct nlmsghdr *nl = (struct nlmsghdr *)buffer;
  struct ifinfomsg *ifi = (struct ifinfomsg *)(NLMSG_DATA(buffer));

  memset(ifi, 0, sizeof(struct ifinfomsg));
  ifi->ifi_family = AF_UNSPEC;
  // ifi->ifi_type = 0;
  ifi->ifi_index =
      ifindex;  // new interface, could be specified since linux 3.7
  ifi->ifi_flags = 0;
  // ifi->ifi_change = 0xffffffff;

  nl->nlmsg_len += NLMSG_LENGTH(sizeof(struct ifinfomsg));

  return 0;
}

int _nl_payload_addr(uint32_t ifindex, uint8_t *buffer, size_t len) {
  struct nlmsghdr *nl = (struct nlmsghdr *)buffer;
  struct ifaddrmsg *addr = (struct ifaddrmsg *)(NLMSG_DATA(buffer));

  memset(addr, 0, sizeof(struct ifaddrmsg));
  addr->ifa_family = AF_UNSPEC;  // INET6;
  /*
     addr->ifa_prefixlen = 128;
     addr->ifa_flags = 0;
     addr->ifa_scope = RT_SCOPE_LINK; //IFA_ADDRESS;
     addr->ifa_index = ifindex;
     */

  nl->nlmsg_len += NLMSG_LENGTH(sizeof(struct ifaddrmsg)) - 4;

  return 0;
}

int _nl_payload_route(uint8_t table_id, uint8_t addr_family, uint8_t dst_len,
                      uint8_t *buffer, size_t len) {
  struct nlmsghdr *nl = (struct nlmsghdr *)buffer;
  struct rtmsg *raddr = (struct rtmsg *)(NLMSG_DATA(buffer));

  raddr->rtm_family = addr_family;
  raddr->rtm_dst_len = dst_len;
  raddr->rtm_src_len = 0;
  raddr->rtm_tos = 0;

  raddr->rtm_table = table_id;
  raddr->rtm_protocol = RTPROT_BOOT;
  raddr->rtm_scope = RT_SCOPE_UNIVERSE;
  raddr->rtm_type = RTN_UNICAST;

  raddr->rtm_flags = 0;

  nl->nlmsg_len += NLMSG_LENGTH(sizeof(struct rtmsg));

  return 0;
}

uint32_t _nl_get_ifid(const char *interface_name) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;
  size_t len = interface_name ? strlen(interface_name) + 1 : 0;
  uint8_t padding[RTA_ALIGNTO] = {0, 0, 0, 0};

  if (len == 0) {
    goto ERR_IF;
  }

  struct {
    struct nlmsghdr hdr;
    struct ifinfomsg payload;
  } msg = {//.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
           .hdr.nlmsg_type = RTM_GETLINK,
           .hdr.nlmsg_flags = FLAGS_GET,
           .payload.ifi_family = AF_UNSPEC,
           .payload.ifi_index = 0};
  struct rtattr a_ifname = {RTA_LENGTH(strlen(interface_name) + 1),
                            IFLA_IFNAME};

  struct iovec iov[] = {{&msg, sizeof(msg)},
                        {&a_ifname, sizeof(a_ifname)},
                        {(char *)interface_name, len},
                        {padding, RTA_SPACE(len) - RTA_LENGTH(len)}};
  msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }
  n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
  if (n == -1) {
    goto ERR_SEND;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
    return 0; /* Unexpected */
  }

  for (; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
    struct ifinfomsg *payload = (struct ifinfomsg *)NLMSG_DATA(hdr);
    return payload->ifi_index;
  }
  return 0;

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
ERR_IF:
  return 0;
}

int _nl_get_output_ifid(const char *ip_address, uint8_t family_address,
                        uint32_t *interface_id) {
  int rc;

  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR;
  }

  if (family_address == AF_INET6) {
    struct in6_addr addr;  // V6SPECIFIC

    struct {
      struct nlmsghdr hdr;
      struct rtmsg payload;
    } msg = {
        .hdr.nlmsg_type = RTM_GETROUTE,
        .hdr.nlmsg_flags = NLM_F_REQUEST,
        .hdr.nlmsg_seq = seq++,
        .payload.rtm_family = AF_INET6,
        .payload.rtm_dst_len = IPV6_ADDR_LEN_BITS,
        .payload.rtm_src_len = 0,
        .payload.rtm_tos = 0,
        .payload.rtm_table = RT_TABLE_UNSPEC,
        .payload.rtm_protocol = RTPROT_UNSPEC,
        .payload.rtm_scope = RT_SCOPE_UNIVERSE,
        .payload.rtm_type = RTN_UNSPEC,
        .payload.rtm_flags = 0  // RTM_F_NOTIFY in 'ip route get'
    };

    /* Convert the IP address to binary form */
    rc = inet_pton(AF_INET6, ip_address, &addr);
    if (rc <= 0) {
      goto ERR;
    }

    /* Set attribute = length/type/value */
    struct rtattr a_dst = {RTA_LENGTH(16), RTA_DST};
    struct iovec iov[] = {
        {&msg, sizeof(msg)},
        {&a_dst, sizeof(a_dst)},  // attribute
        {&addr, sizeof(addr)}     // value
    };
    msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

    n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
    if (n == -1) {
      goto ERR;
    }
  } else if (family_address == AF_INET) {
    struct in_addr addr;

    struct {
      struct nlmsghdr hdr;
      struct rtmsg payload;
    } msg = {
        .hdr.nlmsg_type = RTM_GETROUTE,
        .hdr.nlmsg_flags = NLM_F_REQUEST,
        .hdr.nlmsg_seq = seq++,
        .payload.rtm_family = AF_INET,
        .payload.rtm_dst_len = IPV4_ADDR_LEN_BITS,
        .payload.rtm_src_len = 0,
        .payload.rtm_tos = 0,
        .payload.rtm_table = RT_TABLE_UNSPEC,
        .payload.rtm_protocol = RTPROT_UNSPEC,
        .payload.rtm_scope = RT_SCOPE_UNIVERSE,
        .payload.rtm_type = RTN_UNSPEC,
        .payload.rtm_flags = 0  // RTM_F_NOTIFY in 'ip route get'
    };

    /* Convert the IP address to binary form */
    rc = inet_pton(AF_INET, ip_address, &addr);
    if (rc <= 0) {
      goto ERR;
    }

    /* Set attribute = length/type/value */
    struct rtattr a_dst = {RTA_LENGTH(4), RTA_DST};
    struct iovec iov[] = {
        {&msg, sizeof(msg)},
        {&a_dst, sizeof(a_dst)},  // attribute
        {&addr, sizeof(addr)}     // value
    };
    msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

    n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
    if (n == -1) {
      goto ERR;
    }
  } else {
    goto ERR;
  }

  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR;
    }
    return HICN_SOCKET_ERROR_UNEXPECTED; /* Unexpected */
  }

  for (; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(hdr);
    int attrlen = RTM_PAYLOAD(hdr);
    struct rtattr *rta;
    for (rta = RTM_RTA(rtm); RTA_OK(rta, attrlen);
         rta = RTA_NEXT(rta, attrlen)) {
      if (rta->rta_type == RTA_OIF) {
        *interface_id = *(uint32_t *)RTA_DATA(rta);
        return HICN_SOCKET_ERROR_NONE;
      }
    }
  }

  return HICN_SOCKET_ERROR_NONE;

ERR:
  return HICN_SOCKET_ERROR_UNSPEC;
}

int _nl_get_ip_addr(uint32_t interface_id, uint8_t address_family,
                    ip_prefix_t *prefix) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  struct {
    struct nlmsghdr hdr;
    struct ifaddrmsg payload;
  } msg = {.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
           .hdr.nlmsg_type = RTM_GETADDR,
           .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT,  // | NLM_F_MATCH,
           .payload.ifa_family = address_family,
           .payload.ifa_index = 0};

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }

  n = send(fd, &msg, sizeof(msg), 0);
  if (n == -1) {
    goto ERR_SEND;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
    return -99; /* Unexpected */
  }

  for (; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
    struct ifaddrmsg *payload = (struct ifaddrmsg *)NLMSG_DATA(hdr);

    if (address_family == AF_INET6) {
      if ((payload->ifa_index == interface_id) &&
          (payload->ifa_prefixlen < IPV6_ADDR_LEN * 8)) {
        memcpy(prefix->address.v6.buffer, RTA_DATA(payload + 1), IPV6_ADDR_LEN);
        prefix->family = AF_INET6;
        prefix->len = IPV6_ADDR_LEN_BITS;
        return HICN_SOCKET_ERROR_NONE;
      }
    } else if (address_family == AF_INET) {
      if ((payload->ifa_index == interface_id) &&
          (payload->ifa_prefixlen < IPV4_ADDR_LEN * 8)) {
        memcpy(prefix->address.v4.buffer, RTA_DATA(payload + 1), IPV4_ADDR_LEN);
        prefix->family = AF_INET;
        prefix->len = IPV4_ADDR_LEN_BITS;
        return HICN_SOCKET_ERROR_NONE;
      }
    } else {
      return -99;
    }
  }

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
  return HICN_SOCKET_ERROR_UNSPEC;
}

int _nl_set_ip_addr(uint32_t interface_id, ip_prefix_t *prefix) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  struct {
    struct nlmsghdr hdr;
    struct ifaddrmsg payload;
  } msg = {
      .hdr.nlmsg_type = RTM_NEWADDR,
      .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_MATCH | NLM_F_ATOMIC,
      .hdr.nlmsg_seq = seq++,
      .payload.ifa_family = prefix->family,
      .payload.ifa_prefixlen = prefix->len,
      .payload.ifa_flags = 0,
      .payload.ifa_scope = RT_SCOPE_UNIVERSE,
      .payload.ifa_index = interface_id};

  /* Set attributes = length/type/value */
  struct rtattr ifa_address = {RTA_LENGTH(ip_address_len(prefix->family)),
                               IFA_ADDRESS};
  const void * address = ip_address_get_buffer(&prefix->address, prefix->family);
  if (!address)
      goto ERR_ADDRESS;
  const struct iovec iov[] = {
      {&msg, sizeof(msg)},
      {&ifa_address, sizeof(ifa_address)},
      {(void*)address, ip_address_len(prefix->family)},
  };
  msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }

  // hicn_packet_dump_iov(iov, ARRAY_SIZE(iov));

  n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
  if (n == -1) {
    goto ERR_SEND;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
  }

  return 0;

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
ERR_ADDRESS:
  return -1;
}

int _nl_up_if(uint32_t interface_id) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }

  struct {
    struct nlmsghdr hdr;
    struct ifinfomsg payload;
  } msg = {
      .hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
      .hdr.nlmsg_type = RTM_NEWLINK,
      .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
      .payload.ifi_family = AF_UNSPEC,
      .payload.ifi_index = interface_id,
      .payload.ifi_flags = IFF_UP,
      .payload.ifi_change = IFF_UP  // 0xffffffff
  };

  n = send(fd, &msg, sizeof(msg), 0);
  if (n == -1) {
    goto ERR_SEND;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
    return 0;
  }

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
  return -1;
}

struct route_info {
  char *dst_addr;
  char *src_addr;
  char *gateway;
  char ifName[IF_NAMESIZE];
};

/*
 * ip -6 route add PREFIX dev INTERFACE_NAME
 */
#if 0
int _nl_add_in_route(const char * prefix, const uint32_t interface_id)
{
    char buffer[BUFSIZE];
    struct nlmsghdr * hdr = (struct nlmsghdr *)buffer;
    size_t n;
    int fd;

    int pton_fd;
    unsigned char dst[sizeof(struct in6_addr)];
    char * p;
    char * eptr;
    char addr[strlen(prefix)];
    uint32_t dst_len;

    strncpy(addr, prefix, strlen(prefix));

    p = strchr(addr, '/');
    if (!p) {
        dst_len = IPV6_ADDR_LEN;
    } else {
        dst_len = strtoul(p + 1, &eptr, 10);
        if (dst_len > IPV6_ADDR_LEN * 8) {
            printf("E: Netmask > IPV6_ADDR_LEN");
            return -1;
        }
        *p = 0;
    }

    pton_fd = inet_pton(AF_INET6, addr, dst);
    if (pton_fd <= 0) {
        if (pton_fd == 0)
            ;//ERROR("Not in presentation format");
        else
            perror("inet_pton");
        return -2;
    }

    _nl_header(RTM_NEWROUTE, (uint8_t *)buffer, BUFSIZE, FLAGS_CREATE_MATCH);
    _nl_payload_route(RT_TABLE_MAIN, dst_len, (uint8_t *)buffer, BUFSIZE);

    addAttr(hdr, BUFSIZE, RTA_DST, dst, IPV6_ADDR_LEN);
    addAttr(hdr, BUFSIZE, RTA_OIF, (void*)&interface_id, sizeof(uint32_t));

    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        goto ERR_SOCKET;
    }

    n = send(fd, buffer, hdr->nlmsg_len, 0);
    if (n == -1) {
        goto ERR_SEND;
    }
    n = recv(fd, buffer, BUFSIZE, 0);
    if (n == -1) {
        goto ERR_RECV;
    }

    if (hdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr * err = (struct nlmsgerr *)NLMSG_DATA(hdr);
        if (err->error < 0) {
            errno = -err->error;
            goto ERR_NL;
        }
        return 0;
    }

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
    return -1;

}
#endif

/*
 * ip -6 route add local default via GATEWAY_IP table TABLE_ID
 */
int _nl_add_out_route(const char *gateway, uint8_t address_family,
                      const uint8_t table_id, int default_route) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  int pton_fd;

  if (address_family == AF_INET) {
    struct in_addr gw;

    pton_fd = inet_pton(AF_INET, gateway, (struct in_addr *)&gw);
    if (pton_fd < 0) {
      return -1;
    }

    _nl_header(RTM_NEWROUTE, (uint8_t *)buffer, BUFSIZE,
               NLM_F_REQUEST | NLM_F_ACK | NLM_F_MATCH | NLM_F_ATOMIC);
    _nl_payload_route(table_id, address_family, 0, (uint8_t *)buffer, BUFSIZE);

    /* gw */
    addAttr(hdr, BUFSIZE, RTA_GATEWAY, &gw, sizeof(gw));

  } else if (address_family == AF_INET6) {
    struct in6_addr gw;

    pton_fd = inet_pton(AF_INET6, gateway, (struct in6_addr *)&gw);
    if (pton_fd < 0) {
      return -1;
    }

    _nl_header(RTM_NEWROUTE, (uint8_t *)buffer, BUFSIZE,
               NLM_F_REQUEST | NLM_F_ACK | NLM_F_MATCH | NLM_F_ATOMIC);
    _nl_payload_route(table_id, address_family, 0, (uint8_t *)buffer, BUFSIZE);

    /* gw */
    addAttr(hdr, BUFSIZE, RTA_GATEWAY, &gw, sizeof(gw));
    if (default_route != -1) {
      addAttr(hdr, BUFSIZE, RTA_OIF, &default_route, sizeof(default_route));
    }

  } else {
    return -1;
  }

  // For more than 255 tables
  // addAttr(msg, BUFSIZE, RTA_TABLE, &table_id, sizeof(uint32_t));

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }

  n = send(fd, buffer, hdr->nlmsg_len, 0);
  if (n == -1) {
    goto ERR_SEND;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
    return 0;
  }

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
  return -1;
}

/*
 * ip -6 route del local default via GATEWAY_IP table TABLE_ID
 */
int _nl_del_out_route(const char *gateway, const uint8_t address_family,
                      const uint8_t table_id) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  int pton_fd;

  if (address_family == AF_INET) {
    struct in_addr gw;

    pton_fd = inet_pton(AF_INET, gateway, (struct in_addr *)&gw);
    if (pton_fd < 0) {
      return -1;
    }

    _nl_header(RTM_DELROUTE, (uint8_t *)buffer, BUFSIZE,
               NLM_F_REQUEST | NLM_F_ACK | NLM_F_MATCH | NLM_F_ATOMIC);
    _nl_payload_route(table_id, address_family, 0, (uint8_t *)buffer, BUFSIZE);

    /* gw */
    addAttr(hdr, BUFSIZE, RTA_GATEWAY, &gw, sizeof(gw));

  } else if (address_family == AF_INET6) {
    struct in6_addr gw;

    pton_fd = inet_pton(AF_INET6, gateway, (struct in6_addr *)&gw);
    if (pton_fd < 0) {
      return -1;
    }

    _nl_header(RTM_DELROUTE, (uint8_t *)buffer, BUFSIZE,
               NLM_F_REQUEST | NLM_F_ACK | NLM_F_MATCH | NLM_F_ATOMIC);
    _nl_payload_route(table_id, address_family, 0, (uint8_t *)buffer, BUFSIZE);

    /* gw */
    addAttr(hdr, BUFSIZE, RTA_GATEWAY, &gw, sizeof(gw));

  } else {
    return -1;
  }

  // For more than 255 tables
  // addAttr(msg, BUFSIZE, RTA_TABLE, &table_id, sizeof(uint32_t));

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }

  n = send(fd, buffer, hdr->nlmsg_len, 0);
  if (n == -1) {
    goto ERR_SEND;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
    return 0;
  }

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
  return -1;
}

/*
 * ip route del 1:2::2 dev lo table local
 *
 */
int _nl_del_lo_route(const ip_prefix_t *prefix) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  struct {
    struct nlmsghdr hdr;
    struct rtmsg payload;
  } msg = {
      .hdr.nlmsg_type = RTM_DELROUTE,
      .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
      .hdr.nlmsg_seq = seq++,
      .payload.rtm_family = prefix->family,
      .payload.rtm_dst_len = prefix->len,
      .payload.rtm_src_len = 0,
      .payload.rtm_tos = 0,
      .payload.rtm_table = RT_TABLE_LOCAL,
      .payload.rtm_protocol = RTPROT_UNSPEC,
      .payload.rtm_scope = RT_SCOPE_UNIVERSE,
      .payload.rtm_type = RTN_UNSPEC,
      .payload.rtm_flags = 0  // RTM_F_NOTIFY in 'ip route get'
  };

  /* Set attribute = length/type/value */
  uint32_t one = 1;
  struct rtattr a_dst = {RTA_LENGTH(ip_address_len(prefix->family)), RTA_DST};
  struct rtattr a_ifid_lo = {RTA_LENGTH(sizeof(uint32_t)), RTA_OIF};
  const void * address = ip_address_get_buffer(&prefix->address, prefix->family);
  if (!address)
      goto ERR;
  const struct iovec iov[] = {
      {&msg, sizeof(msg)},
      /* Ip address */
      {&a_dst, sizeof(a_dst)},
      {(void*)address, ip_address_len(prefix->family)},
      /* Interface id */
      {&a_ifid_lo, sizeof(a_ifid_lo)},
      {&one, sizeof(one)}};
  msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR;
  }

  n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
  if (n == -1) {
    goto ERR;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR;
    }
    return 0;
  }

  return HICN_SOCKET_ERROR_NONE;
ERR:
  return HICN_SOCKET_ERROR_UNSPEC;
}

/*
 * ip -6 rule add iif INTERFACE_NAME lookup TABLE_ID
 */
int _nl_add_rule(const char *interface_name, uint8_t address_family,
                 const uint8_t table_id) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  _nl_header(RTM_NEWRULE, (uint8_t *)buffer, BUFSIZE, FLAGS_CREATE);
  _nl_payload_rule(table_id, address_family, (uint8_t *)buffer, BUFSIZE);

  addAttr(hdr, BUFSIZE, FRA_IIFNAME, (void *)interface_name,
          strlen(interface_name));

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }

  n = send(fd, buffer, hdr->nlmsg_len, 0);
  if (n == -1) {
    goto ERR_SEND;
  }
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
    return 0;
  }

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
  return -1;
}

/*
 * ip -6 rule del iif INTERFACE_NAME //lookup TABLE_ID
 */
int _nl_del_rule(const char *interface_name, uint8_t address_family,
                 const uint8_t table_id) {
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;
  size_t n;
  int fd;

  _nl_header(RTM_DELRULE, (uint8_t *)buffer, BUFSIZE, FLAGS_CREATE);
  _nl_payload_rule(table_id, address_family, (uint8_t *)buffer, BUFSIZE);

  addAttr(hdr, BUFSIZE, FRA_IIFNAME, (void *)interface_name,
          strlen(interface_name));

  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR_SOCKET;
  }

  n = send(fd, buffer, hdr->nlmsg_len, 0);
  if (n == -1) {
    goto ERR_SEND;
  }

  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR_RECV;
  }

  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR_NL;
    }
    return 0;
  }

ERR_NL:
ERR_RECV:
ERR_SEND:
ERR_SOCKET:
  return -1;
}

/*
 * ip -6 neigh add proxy 1:2::2 dev hicnc-cons-eth0 2>&1 | grep nei
 *
 */
int _nl_add_neigh_proxy(const ip_prefix_t *prefix,
                        const uint32_t interface_id) {
  /* Buffer for holding the response, with appropriate casting on the header */
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;

  /* Used for send and receive operations on netlink socket */
  int fd;
  size_t n;

  /* Packet header */
  struct {
    struct nlmsghdr hdr;
    struct ndmsg payload;
  } msg = {
      .hdr.nlmsg_type = RTM_NEWNEIGH,
      .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_EXCL,
      .hdr.nlmsg_seq = seq++,
      .payload.ndm_family = prefix->family,
      .payload.ndm_ifindex = interface_id,
      .payload.ndm_state = NUD_PERMANENT,
      .payload.ndm_flags = NTF_PROXY,
  };

  /* Message attributes = length/type/value */
  struct rtattr a_dst = {RTA_LENGTH(ip_address_len(prefix->family)), NDA_DST};

  const void * address = ip_address_get_buffer(&prefix->address, prefix->family);
  if (!address)
      goto ERR;

  /* Iovec describing the packets */
  const struct iovec iov[] = {
      {&msg, sizeof(msg)},
      /* Ip address */
      {&a_dst, sizeof(a_dst)},
      {(void*)address, ip_address_len(prefix->family)},
  };
  msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

  /* Open netlink socket */
  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR;
  }

  /* Send packet */
  n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
  if (n == -1) {
    goto ERR;
  }

  /* Receive answer */
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR;
  }

  /* Parse answer */
  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR;
    }
  }

  return HICN_SOCKET_ERROR_NONE;
ERR:
  return HICN_SOCKET_ERROR_UNSPEC;
}

/* ip -6 route add 0:1::/64 dev hicn-if0 table 100 */
/* ip -6 route add 0:2::/64 dev hicn-if1 table 100 */
int _nl_add_in_route_table(const ip_prefix_t *prefix,
                           const uint32_t interface_id,
                           const uint8_t table_id) {
  /* Buffer for holding the response, with appropriate casting on the header */
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;

  /* Used for send and receive operations on netlink socket */
  int fd;
  size_t n;

  /* Packet header */
  struct {
    struct nlmsghdr hdr;
    struct rtmsg payload;
  } msg = {
      .hdr.nlmsg_type = RTM_NEWROUTE,
      .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_EXCL,
      .hdr.nlmsg_seq = seq++,
      .payload.rtm_family = prefix->family,
      .payload.rtm_dst_len = prefix->len,
      .payload.rtm_src_len = 0,
      .payload.rtm_tos = 0,
      .payload.rtm_table = table_id, /* RT_TABLE_MAIN, etc. */
      .payload.rtm_protocol = RTPROT_BOOT,
      .payload.rtm_scope =
          prefix->family == AF_INET6 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK,
      .payload.rtm_type = RTN_UNICAST,
      .payload.rtm_flags = 0,
  };

  /* Message attributes = length/type/value */
  struct rtattr a_dst = {RTA_LENGTH(ip_address_len(prefix->family)), RTA_DST};
  struct rtattr a_oif = {RTA_LENGTH(sizeof(uint32_t)), RTA_OIF};

  const void * address = ip_address_get_buffer(&prefix->address, prefix->family);
  if (!address)
      goto ERR;

  /* Iovec describing the packets */
  const struct iovec iov[] = {
      {&msg, sizeof(msg)},
      /* Destination prefix / ip address */
      {&a_dst, sizeof(a_dst)},
      {(void*)address, ip_address_len(prefix->family)},
      /* Output interface */
      {&a_oif, sizeof(a_oif)},
      {(void *)&interface_id, sizeof(uint32_t)},
  };
  msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

  /* Open netlink socket */
  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR;
  }

  /* Send packet */
  n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
  if (n == -1) {
    goto ERR;
  }

  /* Receive answer */
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR;
  }

  /* Parse answer */
  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR;
    }
  }

  return HICN_SOCKET_ERROR_NONE;
ERR:
  return HICN_SOCKET_ERROR_UNSPEC;
}

/* Additional helper functions */

int _nl_add_in_route_table_s(const char *prefix, const uint32_t interface_id,
                             const uint8_t table_id) {
  int rc;
  ip_prefix_t ip_address;

  rc = ip_prefix_pton(prefix, &ip_address);
  if (rc < 0) {
    return rc;
  }

  return _nl_add_in_route_table(&ip_address, interface_id, table_id);
}

int _nl_add_in_route_s(const char *prefix, const uint32_t interface_id) {
  return _nl_add_in_route_table_s(prefix, interface_id, RT_TABLE_MAIN);
}

/* ip -6 rule add from b001::/16 prio 0 table 100 */
int _nl_add_prio_rule(const ip_prefix_t *prefix, uint8_t address_family,
                      const uint32_t priority, const uint8_t table_id) {
  /* Buffer for holding the response, with appropriate casting on the header */
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;

  /* Used for send and receive operations on netlink socket */
  int fd;
  size_t n;

  /* Packet header */
  struct {
    struct nlmsghdr hdr;
    struct fib_rule_hdr payload;
  } msg = {
      .hdr.nlmsg_type = RTM_NEWRULE,
      .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_EXCL,
      .hdr.nlmsg_seq = seq++,
      .payload.family = address_family,
      //.payload.dst_len = ,
      .payload.src_len = prefix ? prefix->len : 0,
      .payload.tos = 0,
      .payload.table = table_id,
      .payload.action = FR_ACT_TO_TBL,
      .payload.flags = NLM_F_REPLACE,  // 0
  };

  /* Open netlink socket */
  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR;
  }

  if (prefix) {
    /* Message attributes = length/type/value */
    struct rtattr a_src = {RTA_LENGTH(ip_address_len(prefix->family)), FRA_SRC};
    struct rtattr a_prio = {RTA_LENGTH(sizeof(uint32_t)), FRA_PRIORITY};

    const void * address = ip_address_get_buffer(&prefix->address, prefix->family);
    if (!address)
        goto ERR;
    /* Iovec describing the packets */
    const struct iovec iov[] = {
        {&msg, sizeof(msg)},
        /* Source prefix / prefix */
        {&a_src, sizeof(a_src)},
        {(void*)address, ip_address_len(prefix->family)},
        /* Priority */
        {&a_prio, sizeof(a_prio)},
        {(void *)&priority, sizeof(uint32_t)},
    };
    msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

    /* Send packet */
    n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
    if (n == -1) {
      goto ERR;
    }
  } else {
    struct rtattr a_prio = {RTA_LENGTH(sizeof(uint32_t)), FRA_PRIORITY};

    /* Iovec describing the packets */
    struct iovec iov[] = {
        {&msg, sizeof(msg)},
        /* Priority */
        {&a_prio, sizeof(a_prio)},
        {(void *)&priority, sizeof(uint32_t)},
    };
    msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

    /* Send packet */
    n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
    if (n == -1) {
      goto ERR;
    }
  }

  /* Receive answer */
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR;
  }

  /* Parse answer */
  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0) {
      errno = -err->error;
      goto ERR;
    }
  }

  return HICN_SOCKET_ERROR_NONE;
ERR:
  return HICN_SOCKET_ERROR_UNSPEC;
}

int _nl_add_lo_prio_rule(const ip_prefix_t *prefix, uint8_t address_family,
                         const uint32_t priority) {
  return _nl_add_prio_rule(prefix, address_family, priority,
                           RT_TABLE_LOCAL);
}

/* ip -6 rule del from all prio 0 table local */
int _nl_del_prio_rule(const ip_prefix_t *prefix, uint8_t address_family,
                      const uint32_t priority, const uint8_t table_id) {
  /* Buffer for holding the response, with appropriate casting on the header */
  char buffer[BUFSIZE];
  struct nlmsghdr *hdr = (struct nlmsghdr *)buffer;

  /* Used for send and receive operations on netlink socket */
  int fd;
  size_t n;

  /* Packet header */
  struct {
    struct nlmsghdr hdr;
    struct fib_rule_hdr payload;
  } msg = {
      .hdr.nlmsg_type = RTM_DELRULE,
      .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_EXCL,
      .hdr.nlmsg_seq = seq++,
      .payload.family = address_family,
      //.payload.dst_len = ,
      .payload.src_len = prefix ? prefix->len : 0,
      .payload.tos = 0,
      .payload.table = table_id,
      .payload.action = FR_ACT_TO_TBL,
      .payload.flags = NLM_F_REPLACE,  // 0
  };

  /* Open netlink socket */
  fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    goto ERR;
  }

  /* Message attributes = length/type/value */
  if (prefix) {
    struct rtattr a_src = {RTA_LENGTH(ip_address_len(prefix->family)), FRA_SRC};
    struct rtattr a_prio = {RTA_LENGTH(sizeof(uint32_t)), FRA_PRIORITY};

    const void * address = ip_address_get_buffer(&prefix->address, prefix->family);
    if (!address)
        goto ERR;

    /* Iovec describing the packets */
    const struct iovec iov[] = {
        {&msg, sizeof(msg)},
        /* Source prefix / prefix */
        {&a_src, sizeof(a_src)},
        {(void*)address, ip_address_len(prefix->family)},
        /* Priority */
        {&a_prio, sizeof(a_prio)},
        {(void *)&priority, sizeof(uint32_t)},
    };
    msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

    /* Send packet */
    n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
    if (n == -1) {
      goto ERR;
    }

  } else {
    struct rtattr a_prio = {RTA_LENGTH(sizeof(uint32_t)), FRA_PRIORITY};

    /* Iovec describing the packets */
    struct iovec iov[] = {
        {&msg, sizeof(msg)},
        /* Priority */
        {&a_prio, sizeof(a_prio)},
        {(void *)&priority, sizeof(uint32_t)},
    };
    msg.hdr.nlmsg_len = iov_length(iov, ARRAY_SIZE(iov));

    /* Send packet */
    n = writev(fd, (struct iovec *)&iov, ARRAY_SIZE(iov));
    if (n == -1) {
      goto ERR;
    }
  }

  /* Receive answer */
  n = recv(fd, buffer, BUFSIZE, 0);
  if (n == -1) {
    goto ERR;
  }

  /* Parse answer */
  if (hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    if (err->error < 0 &&
        err->error != -2) {  //-2 is not such file or directory
      errno = -err->error;
      goto ERR;
    }
  }

  return HICN_SOCKET_ERROR_NONE;
ERR:
  return HICN_SOCKET_ERROR_UNSPEC;
}

int _nl_del_lo_prio_rule(const ip_prefix_t *ip_address, uint8_t address_family,
                         const uint32_t priority) {
  return _nl_del_prio_rule(ip_address, address_family, priority,
                           RT_TABLE_LOCAL);
}

/******************************************************************************/

// #include <net/if.h>
// duplicate declarations, in the meantime
#ifndef __ANDROID__
#define IF_NAMESIZE 16
#endif
//#define WITH_TUN_PI 1

#ifdef WITH_TUN_PI
#define TUN_FLAGS IFF_TUN
#else
#define TUN_FLAGS IFF_TUN | IFF_NO_PI
#endif

/*
 * Taken from Kernel Documentation/networking/tuntap.txt
 */

int tun_alloc(char *dev, int flags) {
  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */

  /* open the clone device */
  if ((fd = open(clonedev, O_RDWR)) < 0) {
    return fd;
  }

  /* preparation of the struct ifr, of type "struct ifreq" */
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    /* if a device name was specified, put it in the structure; otherwise,
     * the kernel will try to allocate the "next" device of the
     * specified type */
    strncpy(ifr.ifr_name, dev, IF_NAMESIZE - 1);
  }

  /* try to create the device */
  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }

  /* if the operation was successful, write back the name of the
   * interface to the variable "dev", so the caller can know
   * it. Note that the caller MUST reserve space in *dev (see calling
   * code below) */
  strcpy(dev, ifr.ifr_name);

  /* this is the special file descriptor that the caller will use to talk
   * with the virtual interface */
  return fd;
}

int linux_get_tun_name(const char *prefix, const char *identifier,
                       char *tun_name) {
  snprintf(tun_name, IF_NAMESIZE, "%s-%s", prefix,
           identifier ? identifier : "main");
  return 0;
}

int linux_tun_enable_offload(int fd) {
  unsigned int offload = 0, tso4 = 1, tso6 = 1, ecn = 1, ufo = 1, csum = 1;

  /* Check if our kernel supports TUNSETOFFLOAD */
  if (ioctl(fd, TUNSETOFFLOAD, 0) != 0 && errno == EINVAL) {
    goto ERR_TUN;
  }

  if (csum) {
    offload |= TUN_F_CSUM;
    if (tso4) offload |= TUN_F_TSO4;
    if (tso6) offload |= TUN_F_TSO6;
    if ((tso4 || tso6) && ecn) offload |= TUN_F_TSO_ECN;
    if (ufo) offload |= TUN_F_UFO;
  }

  if (ioctl(fd, TUNSETOFFLOAD, offload) != 0) {
    offload &= ~TUN_F_UFO;
    if (ioctl(fd, TUNSETOFFLOAD, offload) != 0) {
      fprintf(stderr, "TUNSETOFFLOAD ioctl() failed: %s\n", strerror(errno));
    }
  }

  return 0;

ERR_TUN:
  return -1;
}

int linux_tun_create(char *name) {
  int fd, rc;

  fd = tun_alloc(name, TUN_FLAGS);
  if (fd < 0) {
    // ERROR("Error connecting to tun/tap interface %s!", name);
    errno = -2;
    goto ERR_TUN;
  }

  rc = linux_tun_enable_offload(fd);
  if (rc < 0) {
    // WARN("Could not enable hardware offload on TUN device");
  } else {
    // INFO("Enabled hardware offload on TUN device");
  }

  return fd;

ERR_TUN:
  return -1;
}

/*
 *
 * interface name can be NULL for all interfaces
 */
int linux_enable_proc(char *path) {
  int ret = 0;
  int fd;

  fd = open(path, O_WRONLY);
  if (fd < 0) {
    return -1;
  }

  if (write(fd, "1", 1) != 1) {
    ret = -2;
  }

  close(fd);
  return ret;
}

int linux_enable_v4_forwarding() {
  return linux_enable_proc("/proc/sys/net/ipv4/ip_forward");
}

int linux_enable_v6_forwarding(char *interface_name) {
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "/proc/sys/net/ipv6/conf/%s/forwarding",
           (interface_name) ? interface_name : "all");

  return linux_enable_proc(path);
}

int linux_enable_ndp_proxy() {
  return linux_enable_proc("/proc/sys/net/ipv6/conf/all/proxy_ndp");
}

const hicn_socket_ops_t ops = {
    .arch = "linux",
    .get_tun_name = linux_get_tun_name,
    .tun_create = linux_tun_create,
    .enable_v4_forwarding = linux_enable_v4_forwarding,
    .enable_v6_forwarding = linux_enable_v6_forwarding,
    .enable_ndp_proxy = linux_enable_ndp_proxy,
    .get_ifid = _nl_get_ifid,
    .get_output_ifid = _nl_get_output_ifid,
    .get_ip_addr = _nl_get_ip_addr,
    .set_ip_addr = _nl_set_ip_addr,
    .up_if = _nl_up_if,
    .add_in_route_table = _nl_add_in_route_table,
    .add_in_route_table_s = _nl_add_in_route_table_s,
    .add_in_route_s = _nl_add_in_route_s,
    .add_out_route = _nl_add_out_route,
    .del_out_route = _nl_del_out_route,
    .del_lo_route = _nl_del_lo_route,
    .add_rule = _nl_add_rule,
    .del_rule = _nl_del_rule,
    .add_neigh_proxy = _nl_add_neigh_proxy,
    .add_prio_rule = _nl_add_prio_rule,
    .add_lo_prio_rule = _nl_add_lo_prio_rule,
    .del_prio_rule = _nl_del_prio_rule,
    .del_lo_prio_rule = _nl_del_lo_prio_rule,
};
