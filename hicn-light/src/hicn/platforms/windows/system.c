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

#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>

#include <errno.h>
#include <string.h>

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#include <hicn/core/forwarder.h>
#include <hicn/utils/interfaceSet.h>

#include <hicn/utils/addressList.h>

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
  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
  ULONG outBufLen = 0;
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
  ULONG family = AF_UNSPEC;

  DWORD dwSize = 0;
  DWORD dwRetVal = 0;
  ULONG Iterations = 0;
  do {
    pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
    if (pAddresses == NULL) {
      printf("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
      exit(1);
    }

    dwRetVal =
        GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      FREE(pAddresses);
      pAddresses = NULL;
    } else {
      break;
    }

    Iterations++;

  } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

  if (dwRetVal == NO_ERROR) {
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
      if (strcmp(pCurrAddresses->AdapterName, ifname)) {
        int mtu = pCurrAddresses->Mtu;
        if (pAddresses) {
          FREE(pAddresses);
        }
        return mtu;
      }
      pCurrAddresses = pCurrAddresses->Next;
    }
  }

  if (pAddresses) {
    FREE(pAddresses);
  }
  return -1;
}

InterfaceSet *system_Interfaces(Forwarder *forwarder) {
  InterfaceSet *set = interfaceSetCreate();

  Logger *logger = forwarder_GetLogger(forwarder);

  DWORD dwSize = 0;
  DWORD dwRetVal = 0;
  unsigned int i = 0;
  // Set the flags to pass to GetAdaptersAddresses
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

  // default to unspecified address family (both)
  ULONG family = AF_UNSPEC;

  LPVOID lpMsgBuf = NULL;

  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  ULONG outBufLen = 0;
  ULONG Iterations = 0;

  PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
  PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
  PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
  PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
  IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;
  IP_ADAPTER_PREFIX *pPrefix = NULL;

  outBufLen = WORKING_BUFFER_SIZE;

  do {
    pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
    parcAssertNotNull(
        pAddresses,
        "Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
    dwRetVal =
        GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      FREE(pAddresses);
      pAddresses = NULL;
    } else {
      break;
    }

    Iterations++;

  } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));
  if (dwRetVal == NO_ERROR) {
    // If successful, output some information from the data we received
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
      if (pCurrAddresses->OperStatus == IfOperStatusUp) {
        Interface *iface =
            interfaceSetGetByName(set, pCurrAddresses->AdapterName);
        if (iface == NULL) {
          pMulticast = pCurrAddresses->FirstMulticastAddress;
          if (pMulticast) {
            for (i = 0; pMulticast != NULL; i++) pMulticast = pMulticast->Next;
          }

          iface = interfaceCreate(
              pCurrAddresses->AdapterName,
              forwarder_GetNextConnectionId(forwarder),
              pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK, i > 0,
              pCurrAddresses->Mtu);

          interfaceSetAdd(set, iface);
          for (pUnicast = pCurrAddresses->FirstUnicastAddress; pUnicast != NULL;
               pUnicast = pUnicast->Next) {
            int family = pUnicast->Address.lpSockaddr->sa_family;

            switch (family) {
              case AF_INET: {
                char *ip = inet_ntoa(
                    ((struct sockaddr_in *)(pUnicast->Address.lpSockaddr))
                        ->sin_addr);
                Address *address = addressCreateFromInet(
                    (struct sockaddr_in *)(pUnicast->Address.lpSockaddr));
                interfaceAddAddress(iface, address);
                break;
              }

              case AF_INET6: {
                char str[INET6_ADDRSTRLEN];
                inet_ntop(
                    AF_INET6,
                    &((struct sockaddr_in6 *)(pUnicast->Address.lpSockaddr))
                         ->sin6_addr,
                    str, INET6_ADDRSTRLEN);
                Address *address = addressCreateFromInet6(
                    (struct sockaddr_in6 *)(pUnicast->Address.lpSockaddr));
                interfaceAddAddress(iface, address);
                break;
              }

              default:
                break;
            }
          }
        }
      }
      pCurrAddresses = pCurrAddresses->Next;
    }
  }

  if (pAddresses) {
    FREE(pAddresses);
  }
  return set;
}

Address *system_GetMacAddressByName(Forwarder *forwarder,
                                    const char *interfaceName) {
  return NULL;
}

unsigned system_InterfaceMtu(Forwarder *forwarder, const char *interfaceName) {
  unsigned mtu = 0;

  return mtu;
}
