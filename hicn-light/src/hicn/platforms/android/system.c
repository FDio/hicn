/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#if 0
#include <errno.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

//#define __USE_MISC
#include <net/if.h>

// to get the list of arp types
#include <net/if_arp.h>

// for the mac address
#include <netpacket/packet.h>

#include <hicn/core/forwarder.h>
#include <hicn/utils/interfaceSet.h>

#include <parc/assert/parc_Assert.h>

#include "ifaddrs.h"

/**
 * Returns the MTU for a named interface
 *
 * On linux, we get the MTU by opening a socket and reading SIOCGIFMTU
 *
 * @param [in] ifname Interface name (e.g. "eth0")
 *
 * @retval number The MTU in bytes
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
static int getMtu(const char *ifname) {
  struct ifreq ifr;
  int fd;

  fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(ifr.ifr_name, ifname);
  ioctl(fd, SIOCGIFMTU, &ifr);

  close(fd);
  return ifr.ifr_mtu;
}

InterfaceSet *system_Interfaces(Forwarder *forwarder) {
  InterfaceSet *set = interfaceSetCreate();

  Logger *logger = forwarder_GetLogger(forwarder);

  // this is the dynamically allocated head of the list
  struct ifaddrs *ifaddr;
  int failure = getifaddrs(&ifaddr);
  parcAssertFalse(failure, "Error getifaddrs: (%d) %s", errno, strerror(errno));

  struct ifaddrs *next;
  for (next = ifaddr; next != NULL; next = next->ifa_next) {
    if ((next->ifa_addr == NULL) || ((next->ifa_flags & IFF_UP) == 0)) {
      continue;
    }

    Interface *iface = interfaceSetGetByName(set, next->ifa_name);
    if (iface == NULL) {
      unsigned mtu = (unsigned)getMtu(next->ifa_name);

      iface = interfaceCreate(
          next->ifa_name, forwarder_GetNextConnectionId(forwarder),
          next->ifa_flags & IFF_LOOPBACK, next->ifa_flags & IFF_MULTICAST, mtu);

      interfaceSetAdd(set, iface);
    }

    int family = next->ifa_addr->sa_family;
    switch (family) {
      case AF_INET: {
        Address *address =
            addressCreateFromInet((struct sockaddr_in *)next->ifa_addr);
        interfaceAddAddress(iface, address);
        break;
      }

      case AF_INET6: {
        Address *address =
            addressCreateFromInet6((struct sockaddr_in6 *)next->ifa_addr);
        interfaceAddAddress(iface, address);
        break;
      }

      case AF_PACKET: {
        struct sockaddr_ll *addr_ll = (struct sockaddr_ll *)next->ifa_addr;

        if (logger_IsLoggable(logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
          logger_Log(logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                     "sockaddr_ll family %d proto %d ifindex %d hatype %d "
                     "pkttype %d halen %d",
                     addr_ll->sll_family, addr_ll->sll_protocol,
                     addr_ll->sll_ifindex, addr_ll->sll_hatype,
                     addr_ll->sll_pkttype, addr_ll->sll_halen);
        }

        switch (addr_ll->sll_hatype) {
          // list of the ARP hatypes we can extract a MAC address from
          case ARPHRD_ETHER:
          // fallthrough
          case ARPHRD_IEEE802: {
            Address *address = addressCreateFromLink(
                (uint8_t *)addr_ll->sll_addr, addr_ll->sll_halen);
            interfaceAddAddress(iface, address);
            break;
          }
          default:
            break;
        }

        break;
      }
    }
  }

  freeifaddrs(ifaddr);
  return set;
}

Address *system_GetMacAddressByName(Forwarder *forwarder,
                                    const char *interfaceName) {
  Address *linkAddress = NULL;

  InterfaceSet *interfaceSet = system_Interfaces(forwarder);
  Interface *interface = interfaceSetGetByName(interfaceSet, interfaceName);

  if (interface) {
    const AddressList *addressList = interfaceGetAddresses(interface);

    size_t length = addressListLength(addressList);
    for (size_t i = 0; i < length && !linkAddress; i++) {
      const Address *a = addressListGetItem(addressList, i);
      if (addressGetType(a) == ADDR_LINK) {
        linkAddress = addressCopy(a);
      }
    }
  }

  interfaceSetDestroy(&interfaceSet);

  return linkAddress;
}

unsigned system_InterfaceMtu(Forwarder *forwarder, const char *interfaceName) {
  unsigned mtu = 0;

  InterfaceSet *interfaceSet = system_Interfaces(forwarder);
  Interface *interface = interfaceSetGetByName(interfaceSet, interfaceName);

  if (interface) {
    mtu = interfaceGetMTU(interface);
  }

  interfaceSetDestroy(&interfaceSet);

  return mtu;
}
#endif