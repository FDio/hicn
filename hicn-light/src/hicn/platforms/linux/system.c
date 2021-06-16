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

#if 0

#include <errno.h>
#include <ifaddrs.h>
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

InterfaceSet *system_Interfaces(forwarder_t * forwarder) {
  InterfaceSet *set = interfaceSetCreate();

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

    address_t * address = (address_t *)next->ifa_addr;
    interfaceAddAddress(iface, address);
  }

  freeifaddrs(ifaddr);
  return set;
}

#if 0
address_t *system_GetMacAddressByName(Forwarder *forwarder,
                                    const char *interfaceName) {
  address_t *linkAddress = NULL;

  InterfaceSet *interfaceSet = system_Interfaces(forwarder);
  Interface *interface = interfaceSetGetByName(interfaceSet, interfaceName);

  if (interface) {
    const AddressList *addressList = interfaceGetAddresses(interface);

    size_t length = addressListLength(addressList);
    for (size_t i = 0; i < length && !linkAddress; i++) {
      const address_t *a = addressListGetItem(addressList, i);
      if (addressGetType(a) == ADDR_LINK) {
        linkAddress = addressCopy(a);
      }
    }
  }

  interfaceSetDestroy(&interfaceSet);

  return linkAddress;
}
#endif 

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
