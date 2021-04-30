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

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <hicn/core/system.h>
#include <hicn/utils/interfaceSet.h>
#include <hicn/utils/punting.h>

#include <hicn/config/configurationListeners.h>
#include <hicn/io/hicnListener.h>
#include <hicn/io/tcpListener.h>
#include <hicn/io/udpListener.h>

#include <hicn/utils/address.h>
#include <hicn/utils/addressList.h>
#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static bool _setupHicnListenerOnInet4(Forwarder *forwarder,
                                      const char *symbolic, Address *address) {
  bool success = false;
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  ListenerOps *ops =
      hicnListener_CreateInet(forwarder, (char *)symbolic, address);
  if (ops != NULL) {
    success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
    parcAssertTrue(success, "Failed to add Hicn listener %s to ListenerSet",
                   symbolic);
  }
#endif /* __APPLE__ _WIN32*/
  return success;
}

static bool _setupHicnListenerOnInet6(Forwarder *forwarder,
                                      const char *symbolic, Address *address) {
  bool success = false;
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  ListenerOps *ops =
      hicnListener_CreateInet6(forwarder, (char *)symbolic, address);
  if (ops != NULL) {
    success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
    parcAssertTrue(success, "Failed to add Hicn listener %s to ListenerSet",
                   symbolic);
  }
#endif /* __APPLE__ _WIN32 */
  return success;
}

bool configurationListeners_Remove(const Configuration *config) {
  Logger *logger = configuration_GetLogger(config);
  if (logger_IsLoggable(logger, LoggerFacility_Config, PARCLogLevel_Warning)) {
    logger_Log(logger, LoggerFacility_Config, PARCLogLevel_Warning, __func__,
               "Removing a listener not supported: ingress %u control %s");
  }

  return false;
}

bool _AddPuntingInet(const Configuration *config, Punting *punting,
                     unsigned ingressId) {
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  struct sockaddr *addr = parcNetwork_SockAddress("0.0.0.0", 1234);
  if (addr == NULL) {
    printf("Error creating address\n");
    return false;
  }

  Address *fakeAddr = addressCreateFromInet((struct sockaddr_in *)addr);

  ListenerOps *listenerOps = listenerSet_Find(
      forwarder_GetListenerSet(configuration_GetForwarder(config)), ENCAP_HICN,
      fakeAddr);
  addressDestroy(&fakeAddr);

  if (listenerOps == NULL) {
    printf("the main listener (IPV4) does not exists\n");
    return false;
  }

  struct sockaddr_in puntingAddr;

  Address *address = puntingGetAddress(punting);
  if (address == NULL) return false;

  bool res = addressGetInet(address, &puntingAddr);
  if (!res) {
    printf("unable to read the punting address\n");
    return false;
  }

  char prefix[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(puntingAddr.sin_addr), prefix, INET_ADDRSTRLEN);

  char len[5];
  sprintf(len, "%d", puntingPrefixLen(punting));

  char *prefixStr =
      malloc(strlen(prefix) + strlen(len) + 2);  //+1 for the zero-terminator
  if (prefixStr == NULL) {
    printf("error while create the prefix string\n");
    return false;
  }
  strcpy(prefixStr, prefix);
  strcat(prefixStr, "/");
  strcat(prefixStr, len);

  res = hicnListener_Punting(listenerOps, prefixStr);
  if (!res) {
    printf("error while adding the punting rule\n");
    return false;
  }

  return true;
#else
  return false;
#endif
}

bool _AddPuntingInet6(const Configuration *config, Punting *punting,
                      unsigned ingressId) {
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  struct sockaddr *addr = parcNetwork_SockAddress("0::0", 1234);
  if (addr == NULL) {
    printf("Error creating address\n");
    return false;
  }

  Address *fakeAddr = addressCreateFromInet6((struct sockaddr_in6 *)addr);

  // comments:
  // EncapType: I use the Hicn encap since the punting is available only for
  // Hicn listeners LocalAddress: The only listern for which we need punting
  // rules is the main one, which has no address
  //              so I create a fake empty address. This need to be consistent
  //              with the address set at creation time

  ListenerOps *listenerOps = listenerSet_Find(
      forwarder_GetListenerSet(configuration_GetForwarder(config)), ENCAP_HICN,
      fakeAddr);
  addressDestroy(&fakeAddr);

  if (listenerOps == NULL) {
    printf("the main listener does not exists\n");
    return false;
  }

  struct sockaddr_in6 puntingAddr;
  bool res = addressGetInet6(puntingGetAddress(punting), &puntingAddr);
  if (!res) {
    printf("unable to read the punting address\n");
    return false;
  }

  char prefix[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(puntingAddr.sin6_addr), prefix, INET6_ADDRSTRLEN);

  char len[5];
  sprintf(len, "%d", puntingPrefixLen(punting));

  char *prefixStr =
      malloc(strlen(prefix) + strlen(len) + 2);  //+1 for the zero-terminator
  if (prefixStr == NULL) {
    printf("error while create the prefix string\n");
    return false;
  }
  strcpy(prefixStr, prefix);
  strcat(prefixStr, "/");
  strcat(prefixStr, len);

  res = hicnListener_Punting(listenerOps, prefixStr);
  if (!res) {
    printf("error while adding the punting rule\n");
    return false;
  }

  return true;
#else
  return false;
#endif
}

//=============     LIGHT COMMAN    ===============

static bool _addEther(Configuration *config, add_listener_command *control,
                      unsigned ingressId) {
  // Not implemented
  return false;
}

/*
 *  Create a new IPV4/TCP listener.
 *
 * @param [in,out] forwarder   The hicn-light forwarder instance
 * @param [in] listenerName    The name of the listener
 * @param [in] addr4           The ipv4 address in network byte order
 * @param [in] port            The port number in network byte order
 * @param [in] interfaceName   The name of the interface to bind the socket
 *
 * return true if success, false otherwise
 */
static bool _setupTcpListenerOnInet(Forwarder *forwarder, char *listenerName, ipv4_addr_t *addr4,
                                    uint16_t *port, char *interfaceName) {
  parcAssertNotNull(listenerName, "Parameter listenerName must be non-null");

  bool success = false;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = *port;
  addr.sin_addr.s_addr = *addr4;

  ListenerOps *ops = tcpListener_CreateInet(forwarder, listenerName, addr, interfaceName);
  if (ops) {
    success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
#if 0
    parcAssertTrue(success, "Failed to add TCP listener on %s to ListenerSet",
                   addressToString(ops->getListenAddress(ops)));
#endif
  }
  return success;
}


/*
 *  Create a new IPV4/UDP listener.
 *
 * @param [in,out] forwarder   The hicn-light forwarder instance
 * @param [in] listenerName    The name of the listener
 * @param [in] addr4           The ipv4 address in network byte order
 * @param [in] port            The port number in network byte order
 * @param [in] interfaceName   The name of the interface to bind the socket
 *
 * return true if success, false otherwise
 */
static bool _setupUdpListenerOnInet(Forwarder *forwarder, char *listenerName, ipv4_addr_t *addr4,
                                    uint16_t *port, char *interfaceName) {
  bool success = false;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = *port;
  addr.sin_addr.s_addr = *addr4;

  ListenerOps *ops = udpListener_CreateInet(forwarder, listenerName, addr, interfaceName);
  if (ops) {
    success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
#if 0
    parcAssertTrue(success, "Failed to add UDP listener on %s to ListenerSet",
                   addressToString(ops->getListenAddress(ops)));
#endif
  }
  return success;
}


/*
 *  Create a new IPV6/TCP listener.
 *
 * @param [in,out] forwarder   The hicn-light forwarder instance
 * @param [in] addr6           The ipv6 address in network byte order
 * @param [in] port            The port number in network byte order
 * @param [in] interfaceName   The name of the interface to bind the socket
 *
 * return true if success, false otherwise
 */
static bool _setupTcpListenerOnInet6Light(Forwarder *forwarder, char *listenerName,
                                          ipv6_addr_t *addr6, uint16_t *port, char *interfaceName,
                                          uint32_t scopeId) {
  bool success = false;

  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = *port;
  addr.sin6_addr = *addr6;
  addr.sin6_scope_id = scopeId;

  ListenerOps *ops = tcpListener_CreateInet6(forwarder, listenerName, addr, interfaceName);
  if (ops) {
    success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
#if 0
    parcAssertTrue(success, "Failed to add TCP6 listener on %s to ListenerSet",
                   addressToString(ops->getListenAddress(ops)));
#endif
  }
  return success;
}


/*
 *  Create a new IPV6/UDP listener.
 *
 * @param [in,out] forwarder   The hicn-light forwarder instance
 * @param [in] listenerName    The name of the listener
 * @param [in] addr6           The ipv6 address in network byte order
 * @param [in] port            The port number in network byte order
 * @param [in] interfaceName   The name of the interface to bind the socket
 *
 * return true if success, false otherwise
 */
static bool _setupUdpListenerOnInet6Light(Forwarder *forwarder, char *listenerName,
                                          ipv6_addr_t *addr6, uint16_t *port, char *interfaceName) {
  bool success = false;

  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = *port;
  addr.sin6_addr = *addr6;
  addr.sin6_scope_id = 0;

  ListenerOps *ops = udpListener_CreateInet6(forwarder, listenerName, addr, interfaceName);
  if (ops) {
    success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
#if 0
    parcAssertTrue(success, "Failed to add UDP6 listener on %s to ListenerSet",
                   addressToString(ops->getListenAddress(ops)));
#endif
  }
  return success;
}

/*
 *  Create a new HICN listener.
 *
 * @param [in] config   The configuration
 * @param [in] control  The control command
 * @param [in] port     The connection id of the command
 *
 * return true if success, false otherwise
 */
bool _addHicn(Configuration *config, add_listener_command *control,
              unsigned ingressId) {
  bool success = false;
  const char *symbolic = control->symbolic;
  Address *localAddress = NULL;

  switch (control->addressType) {
    case ADDR_INET: {
      localAddress =
          addressFromInaddr4Port(&control->address.v4.as_u32, &control->port);
      success = _setupHicnListenerOnInet4(configuration_GetForwarder(config),
                                          symbolic, localAddress);
      break;
    }

    case ADDR_INET6: {
      localAddress =
          addressFromInaddr6Port(&control->address.v6.as_in6addr, &control->port);
      success = _setupHicnListenerOnInet6(configuration_GetForwarder(config),
                                          symbolic, localAddress);
      break;
    }

    default:
      if (logger_IsLoggable(configuration_GetLogger(config),
                            LoggerFacility_Config, PARCLogLevel_Warning)) {
        logger_Log(configuration_GetLogger(config), LoggerFacility_Config,
                   PARCLogLevel_Warning, __func__,
                   "Unsupported address type for HICN (ingress id %u): "
                   "must be either IPV4 or IPV6",
                   ingressId);
      }
      break;
  }

  if (success == true && localAddress != NULL) {
    if (logger_IsLoggable(configuration_GetLogger(config),
                          LoggerFacility_Config, PARCLogLevel_Info)) {
      char * str = addressToString(localAddress);
      logger_Log(configuration_GetLogger(config), LoggerFacility_Config,
                 PARCLogLevel_Info, __func__,
                 "Setup hicn listener on address %s",
                 str);
      parcMemory_Deallocate((void **)&str);
    }
  }

  addressDestroy(&localAddress);

  return success;
}

bool _addIP(Configuration *config, add_listener_command *control,
            unsigned ingressId) {
  bool success = false;
  char *symbolic = control->symbolic;

  switch (control->addressType) {
    case ADDR_INET: {

      if (control->connectionType == UDP_CONN) {
        success =
            _setupUdpListenerOnInet(configuration_GetForwarder(config), symbolic,
                                    &control->address.v4.as_u32, &control->port, control->interfaceName);
      } else if (control->connectionType == TCP_CONN) {
        success =
            _setupTcpListenerOnInet(configuration_GetForwarder(config), symbolic,
                                    &control->address.v4.as_u32, &control->port, control->interfaceName);
      }
      break;
    }

    case ADDR_INET6: {
      if (control->connectionType == UDP_CONN) {
        success = _setupUdpListenerOnInet6Light(
            configuration_GetForwarder(config), symbolic, &control->address.v6.as_in6addr,
            &control->port, control->interfaceName);
      } else if (control->connectionType == TCP_CONN) {
        success = _setupTcpListenerOnInet6Light(
            configuration_GetForwarder(config), symbolic, &control->address.v6.as_in6addr,
            &control->port, control->interfaceName, 0);
      }
      break;
    }

    default:
      if (logger_IsLoggable(configuration_GetLogger(config),
                            LoggerFacility_Config, PARCLogLevel_Warning)) {
        char *addrStr = utils_CommandAddressToString(
            control->addressType, &control->address, &control->port);
        logger_Log(
            configuration_GetLogger(config), LoggerFacility_Config,
            PARCLogLevel_Warning, __func__,
            "Unsupported address type for IP encapsulation ingress id %u: %s",
            ingressId, addrStr);
        parcMemory_Deallocate((void **)&addrStr);
      }
      break;
  }

  if (success) {
    if (logger_IsLoggable(configuration_GetLogger(config),
                          LoggerFacility_Config, PARCLogLevel_Info)) {
      char *addrStr = utils_CommandAddressToString(
          control->addressType, &control->address, &control->port);
      logger_Log(configuration_GetLogger(config), LoggerFacility_Config,
                 PARCLogLevel_Info, __func__, "Setup listener on address %s",
                 addrStr);
      parcMemory_Deallocate((void **)&addrStr);
    }
  }

  return success;
}

struct iovec *configurationListeners_Add(Configuration *config,
                                         struct iovec *request,
                                         unsigned ingressId) {
  header_control_message *header = request[0].iov_base;
  add_listener_command *control = request[1].iov_base;

  bool success = false;

  ListenerSet *listenerSet = forwarder_GetListenerSet(configuration_GetForwarder(config));
  int listenerId = listenerSet_FindIdByListenerName(listenerSet, control->symbolic);

  if (listenerId < 0) {
    if (control->listenerMode == ETHER_MODE) {
      parcTrapNotImplemented("Add Ethernet Listener is not supported");
      success = _addEther(config, control, ingressId);
      // it is a failure
    } else if (control->listenerMode == IP_MODE) {
      success = _addIP(config, control, ingressId);
    } else if (control->listenerMode == HICN_MODE) {
      success = _addHicn(config, control, ingressId);
    } else {
      Logger *logger = configuration_GetLogger(config);
      if (logger_IsLoggable(logger, LoggerFacility_Config,
                            PARCLogLevel_Warning)) {
        logger_Log(logger, LoggerFacility_Config, PARCLogLevel_Warning, __func__,
                   "Unsupported encapsulation mode (ingress id %u)", ingressId);
      }
    }
  }

  // generate ACK/NACK
  struct iovec *response;

  if (success) {  // ACK
    response = utils_CreateAck(header, control, sizeof(add_listener_command));
  } else {  // NACK
    response = utils_CreateNack(header, control, sizeof(add_listener_command));
  }

  return response;
}

struct iovec *configurationListeners_AddPunting(Configuration *config,
                                                struct iovec *request,
                                                unsigned ingressId) {
  header_control_message *header = request[0].iov_base;
  add_punting_command *control = request[1].iov_base;

  const char *symbolicOrConnid = control->symbolicOrConnid;
  uint32_t len = control->len;
  in_port_t port = htons(1234);
  bool success = false;

  if (control->addressType == ADDR_INET) {
    Address *address = addressFromInaddr4Port(&control->address.v4.as_u32, &port);
    Punting *punting = puntingCreate(symbolicOrConnid, address, len);
    success = _AddPuntingInet(config, punting, ingressId);
    addressDestroy(&address);
  } else if (control->addressType == ADDR_INET6) {
    Address *address = addressFromInaddr6Port(&control->address.v6.as_in6addr, &port);
    Punting *punting = puntingCreate(symbolicOrConnid, address, len);
    success = _AddPuntingInet6(config, punting, ingressId);
    addressDestroy(&address);
  } else {
    printf("Invalid IP type.\n");  // will generate a Nack
    return utils_CreateNack(header, control, sizeof(add_punting_command));
  }

  // generate ACK/NACK
  struct iovec *response;
  if (success) {  // ACK
    response = utils_CreateAck(header, control, sizeof(add_punting_command));
  } else {  // NACK
    response = utils_CreateNack(header, control, sizeof(add_punting_command));
  }

  return response;
}

//===========================       INITIAL LISTENERS ====================

static void _setupListenersOnAddress(Forwarder *forwarder, char *listenerName,
                                     const Address *address, uint16_t port,
                                     char *interfaceName) {
  address_type type = addressGetType(address);
  switch (type) {
    case ADDR_INET: {
      struct sockaddr_in tmp;
      addressGetInet(address, &tmp);
      _setupTcpListenerOnInet(forwarder, listenerName, &tmp.sin_addr.s_addr, &port, interfaceName);
      break;
    }

    case ADDR_INET6: {
      struct sockaddr_in6 tmp;
      addressGetInet6(address, &tmp);
      _setupTcpListenerOnInet6Light(forwarder, listenerName, &tmp.sin6_addr, &port, interfaceName,
                                    tmp.sin6_scope_id);
      break;
    }

    case ADDR_LINK:
      // not used
      break;

    default:
      // dont' know how to handle this, so no listeners
      break;
  }
}

void configurationListeners_SetupAll(const Configuration *config, uint16_t port,
                                     const char *localPath) {
  Forwarder *forwarder = configuration_GetForwarder(config);
  InterfaceSet *set = system_Interfaces(forwarder);

  size_t interfaceSetLen = interfaceSetLength(set);
  for (size_t i = 0; i < interfaceSetLen; i++) {
    Interface *iface = interfaceSetGetByOrdinalIndex(set, i);

    const AddressList *addresses = interfaceGetAddresses(iface);
    size_t addressListLen = addressListLength(addresses);

    for (size_t j = 0; j < addressListLen; j++) {
      const Address *address = addressListGetItem(addresses, j);

      // Do not start on link address
      char listenerName[SYMBOLIC_NAME_LEN];
#if defined(__ANDROID__) || defined(_WIN32)
      snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%zu", i);
#else
      snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%ld", i);
#endif
      if (addressGetType(address) != ADDR_LINK) {
        _setupListenersOnAddress(forwarder, listenerName, address, port,
                                 (char *)interfaceGetName(iface));
      }
    }
  }

  interfaceSetDestroy(&set);
}

void configurationListeners_SetutpLocalIPv4(const Configuration *config,
                                            uint16_t port) {
  Forwarder *forwarder = configuration_GetForwarder(config);
  in_addr_t addr = inet_addr("127.0.0.1");
  uint16_t network_byte_order_port = htons(port);

  char listenerNameUdp[SYMBOLIC_NAME_LEN] = "lo_udp";
  char listenerNameTcp[SYMBOLIC_NAME_LEN] = "lo_tcp";
  char *loopback_interface = "lo";
  _setupUdpListenerOnInet(forwarder, listenerNameUdp,(ipv4_addr_t *)&(addr),
                          &network_byte_order_port, loopback_interface);
  _setupTcpListenerOnInet(forwarder, listenerNameTcp, (ipv4_addr_t *)&(addr),
                          &network_byte_order_port, loopback_interface);
}
