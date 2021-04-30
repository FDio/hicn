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

#include <errno.h>
#include <ifaddrs.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <sys/socket.h>

#include <parc/assert/parc_Assert.h>

#include <hicn/utils/interfaceSet.h>

#include <hicn/core/forwarder.h>
#include <hicn/core/system.h>

InterfaceSet *system_Interfaces(Forwarder *forwarder) {
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

    // This assumes the LINK address comes first so we can get the MTU
    // when the interface is created.

    Interface *iface = interfaceSetGetByName(set, next->ifa_name);
    if (iface == NULL) {
      unsigned mtu = 0;

      if (next->ifa_data != NULL) {
        struct if_data *ifdata = (struct if_data *)next->ifa_data;
        mtu = ifdata->ifi_mtu;
      }

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

      case AF_LINK: {
        struct sockaddr_dl *addr_dl = (struct sockaddr_dl *)next->ifa_addr;

        // skip links with 0-length address
        if (addr_dl->sdl_alen > 0) {
          // addr_dl->sdl_data[12] contains the interface name followed by the
          // MAC address, so need to offset in to the array past the interface
          // name.
          Address *address = addressCreateFromLink(
              (uint8_t *)&addr_dl->sdl_data[addr_dl->sdl_nlen],
              addr_dl->sdl_alen);
          interfaceAddAddress(iface, address);
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

  if (interfaceName) {
    InterfaceSet *interfaceSet = system_Interfaces(forwarder);
    Interface *interface = interfaceSetGetByName(interfaceSet, interfaceName);

    if (interface) {
      mtu = interfaceGetMTU(interface);
    }

    interfaceSetDestroy(&interfaceSet);
  }
  return mtu;
}
