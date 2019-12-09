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

//#include <hicn/core/system.h>
//#include <hicn/utils/interfaceSet.h>
#include <hicn/utils/punting.h>

#include <hicn/config/configurationListeners.h>
#include <hicn/io/hicnListener.h>
#include <hicn/io/tcpListener.h>
#include <hicn/io/udpListener.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

#define INFO(FMT, ...) do {                                                     \
  Logger *logger = configuration_GetLogger(config);                             \
  if (logger_IsLoggable(logger, LoggerFacility_Config, PARCLogLevel_Info))      \
    logger_Log(logger, LoggerFacility_Config, PARCLogLevel_Info, __func__,      \
               FMT, ## __VA_ARGS__);                                            \
} while(0);

#define WARN(FMT, ...) do {                                                     \
  Logger *logger = configuration_GetLogger(config);                             \
  if (logger_IsLoggable(logger, LoggerFacility_Config, PARCLogLevel_Warning))   \
    logger_Log(logger, LoggerFacility_Config, PARCLogLevel_Warning, __func__,   \
               FMT, ## __VA_ARGS__);                                            \
} while(0);

#define ERROR(FMT, ...) do {                                                    \
  Logger *logger = configuration_GetLogger(config);                             \
  if (logger_IsLoggable(logger, LoggerFacility_Config, PARCLogLevel_Error))     \
    logger_Log(logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,     \
               FMT, ## __VA_ARGS__);                                            \
} while(0);

#define DEFAULT_PORT 1234

static
bool
_setupHicnListenerOnInet4(Configuration * config, const char *symbolic,
        address_t * address)
{
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  Forwarder * forwarder = configuration_GetForwarder(config);
  ListenerOps *listener = hicnListener_CreateInet(forwarder, (char *)symbolic,
          address);
  if (!listener)
    return false;

  listener_table_t * table = forwarder_GetListenerTable(forwarder);
  if (!listener_table_add(table, listener)) {
    ERROR("Failed to add Hicn listener %s to ListenerSet", symbolic);
    return false;
  }
  return true;
#else
  return false;
#endif /* __APPLE__ _WIN32 */
}

static
bool
_setupHicnListenerOnInet6(Configuration * config, const char *symbolic,
        address_t * address)
{
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  Forwarder * forwarder = configuration_GetForwarder(config);
  ListenerOps *listener = hicnListener_CreateInet6(forwarder, (char *)symbolic,
          address);
  if (!listener)
    return false;

  listener_table_t * table = forwarder_GetListenerTable(forwarder);
  if (!listener_table_add(table, listener)) {
    ERROR("Failed to add Hicn listener %s to ListenerSet", symbolic);
    return false;
  }
  return true;
#else
  return false;
#endif /* __APPLE__ _WIN32 */
}

bool
configurationListeners_Remove(const Configuration *config)
{
  WARN("Removing a listener is not supported");
  return false;
}

bool
_AddPuntingInet(const Configuration *config, Punting * punting,
        unsigned ingressId)
{
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  address_t fakeaddr = ADDRESS4_ANY(DEFAULT_PORT);

  Forwarder * forwarder = configuration_GetForwarder(config);
  listener_table_t * table = forwarder_GetListenerTable(forwarder);
  ListenerOps *listener = listener_table_lookup(table, ENCAP_HICN, &fakeaddr);
  if (!listener) {
    ERROR("the main listener (IPV4) does not exist");
    return false;
  }

  address_t * address = puntingGetAddress(punting);
  if (address == NULL) return false;

  char prefix[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &address4_ip(&fakeaddr).s_addr, prefix, INET_ADDRSTRLEN);

  char len[5];
  snprintf(len, 5, "%d", puntingPrefixLen(punting));

  char *prefixStr =
      malloc(strlen(prefix) + strlen(len) + 2);  //+1 for the zero-terminator
  if (!prefixStr) {
    ERROR("error while create the prefix string\n");
    return false;
  }
  strcpy(prefixStr, prefix);
  strcat(prefixStr, "/");
  strcat(prefixStr, len);

  if (!hicnListener_Punting(listener, prefixStr)) {
    ERROR("error while adding the punting rule\n");
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
  address_t fakeaddr = ADDRESS6_ANY(DEFAULT_PORT);

  // comments:
  // EncapType: I use the Hicn encap since the punting is available only for
  // Hicn listeners LocalAddress: The only listern for which we need punting
  // rules is the main one, which has no address
  //              so I create a fake empty address. This need to be consistent
  //              with the address set at creation time

  Forwarder * forwarder = configuration_GetForwarder(config);
  listener_table_t * table = forwarder_GetListenerTable(forwarder);
  ListenerOps *listener = listener_table_lookup(table, ENCAP_HICN, &fakeaddr);
  if (!listener) {
    ERROR("the main listener (IPV6) does not exist");
    return false;
  }

  char prefix[INET6_ADDRSTRLEN];

  char len[5];
  snprintf(len, 5, "%d", puntingPrefixLen(punting));

  char *prefixStr = malloc(strlen(prefix) + strlen(len) + 2);  // +1 for the zero-terminator
  if (!prefixStr) {
    ERROR("error while create the prefix string\n");
    return false;
  }
  strcpy(prefixStr, prefix);
  strcat(prefixStr, "/");
  strcat(prefixStr, len);

  if (!hicnListener_Punting(listener, prefixStr)) {
    ERROR("error while adding the punting rule\n");
    return false;
  }

  return true;
#else
  return false;
#endif
}

//=============     LIGHT COMMAND    ===============

static
bool
_addEther(Configuration *config, add_listener_command *control,
                      unsigned ingressId) {
  // Not implemented
  return false;
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
bool
_addHicn(Configuration *config, add_listener_command *control,
        unsigned ingressId)
{
  const char *symbolic = control->symbolic;

  address_t local_addr;
  if (address_from_ip_port(&local_addr, control->family, &control->address, control->port) < 0) {
      WARN("Unsupported address type for HICN (ingress id %u): "
                   "must be either IPV4 or IPV6", ingressId);
      return false;
  }

  switch(control->family) {
    case AF_INET:
      if (!_setupHicnListenerOnInet4(config, symbolic, &local_addr))
        return false;
      break;
    case AF_INET6:
      if (!_setupHicnListenerOnInet6(config, symbolic, &local_addr))
        return false;
      break;
    default:
      return false;
  }

// XXX TODO
#if 0
  INFO("Setup hicn listener on address %s", addressToString(localAddress));
#endif
  return true;
}

static
bool
_setupUdpListener(Forwarder *forwarder, char *listenerName,
        const address_t * address, char * interfaceName)
{
  ListenerOps * listener = udpListener_Create(forwarder, listenerName,
          address, interfaceName);
  if (!listener)
    return false;
  listener_table_t * table = forwarder_GetListenerTable(forwarder);
  if (!listener_table_add(table, listener))
    return false;

  return true;
}

static
bool
_setupTcpListener(Forwarder *forwarder, char *listenerName,
        const address_t * address, char * interfaceName)
{
  ListenerOps * listener = tcpListener_Create(forwarder, listenerName,
          address, interfaceName);
  if (!listener)
    return false;
  listener_table_t * table = forwarder_GetListenerTable(forwarder);
  if (!listener_table_add(table, listener))
    return false;

  return true;
}

bool
_addIP(Configuration *config, add_listener_command *control,
            unsigned ingressId)
{
  Forwarder * forwarder = configuration_GetForwarder(config);

  address_t address;
  if (address_from_ip_port(&address, control->family, &control->address,
              control->port) < 0)
    return false;

  switch(control->connectionType) {
    case UDP_CONN:
      if (!_setupUdpListener(forwarder, control->symbolic, &address,
                  control->interfaceName))
        return false;
      break;
    case TCP_CONN:
      if (!_setupTcpListener(forwarder, control->symbolic, &address,
                  control->interfaceName))
        return false;
      break;
    default:
// XXX TODO
#if 0
      if (logger_IsLoggable(configuration_GetLogger(config),
                            LoggerFacility_Config, PARCLogLevel_Warning)) {
        char *addrStr = utils_CommandAddressToString(
            control->family, &control->address, &control->port);
        logger_Log(
            configuration_GetLogger(config), LoggerFacility_Config,
            PARCLogLevel_Warning, __func__,
            "Unsupported address type for IP encapsulation ingress id %u: %s",
            ingressId, addrStr);
        parcMemory_Deallocate((void **)&addrStr);
      }
#endif
      return false;
  }

// XXX TODO
#if 0
  if (success) {
    if (logger_IsLoggable(configuration_GetLogger(config),
                          LoggerFacility_Config, PARCLogLevel_Info)) {
      char *addrStr = utils_CommandAddressToString(
          control->family, &control->address, &control->port);
      logger_Log(configuration_GetLogger(config), LoggerFacility_Config,
                 PARCLogLevel_Info, __func__, "Setup listener on address %s",
                 addrStr);
      parcMemory_Deallocate((void **)&addrStr);
    }
  }
#endif

  return true;
}

struct iovec *
configurationListeners_Add(Configuration *config, struct iovec *request,
        unsigned ingressId)
{
  header_control_message *header = request[0].iov_base;
  add_listener_command *control = request[1].iov_base;

  Forwarder * forwarder = configuration_GetForwarder(config);
  listener_table_t * table = forwarder_GetListenerTable(forwarder);

  /* Verify that the listener DOES NOT exist */
  ListenerOps * listener = listener_table_get_by_name(table, control->symbolic);
  if (listener)
    goto NACK;

  switch(control->listenerMode) {
    case ETHER_MODE:
      if (!_addEther(config, control, ingressId)) {
        ERROR("Add Ethernet Listener is not supported.");
        goto NACK;
      }
      break;

    case IP_MODE:
      if (!_addIP(config, control, ingressId))
        goto NACK;
      break;

    case HICN_MODE:
      if (!_addHicn(config, control, ingressId))
        goto NACK;
      break;

    default:
      ERROR("Unsupported encapsulation mode (ingress id %u)", ingressId);
      goto NACK;
  }

  return utils_CreateAck(header, control, sizeof(add_listener_command));

NACK:
  return utils_CreateNack(header, control, sizeof(add_listener_command));
}

struct iovec *
configurationListeners_AddPunting(Configuration *config, struct iovec *request,
        unsigned ingressId)
{
  header_control_message *header = request[0].iov_base;
  add_punting_command *control = request[1].iov_base;

  address_t address;
  Punting * punting;

  if (address_from_ip_port(&address, control->family, &control->address,
              DEFAULT_PORT) < 0) {
      ERROR("Invalid IP type.");
      goto NACK;
  }

  punting = puntingCreate(control->symbolicOrConnid, &address, control->len);

  // TODO XXX this could be optimized
  switch(control->family) {
    case AF_INET:
      if (!_AddPuntingInet(config, punting, ingressId))
        goto NACK;
      break;
    case AF_INET6:
      if (!_AddPuntingInet6(config, punting, ingressId))
        goto NACK;
      break;
    default:
      break;
  }

  return utils_CreateAck(header, control, sizeof(add_punting_command));

NACK:
  return utils_CreateNack(header, control, sizeof(add_punting_command));
}

//===========================       INITIAL LISTENERS ====================

// XXX TODO
void
configurationListeners_SetupAll(const Configuration *config, uint16_t port,
        const char *localPath)
{
#if 0
    // XXX TODO
  Forwarder *forwarder = configuration_GetForwarder(config);
  InterfaceSet *set = system_Interfaces(forwarder);

  size_t interfaceSetLen = interfaceSetLength(set);
  for (size_t i = 0; i < interfaceSetLen; i++) {
    Interface *iface = interfaceSetGetByOrdinalIndex(set, i);

    const AddressList *addresses = interfaceGetAddresses(iface);
    size_t addressListLen = addressListLength(addresses);

    for (size_t j = 0; j < addressListLen; j++) {
      const address_t *address = addressListGetItem(addresses, j);

      // Do not start on link address
      char listenerName[SYMBOLIC_NAME_LEN];
#ifdef __ANDROID__
      snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%zu", i);
#else
      snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%ld", i);
#endif
// XXX TODO      if (addressGetType(address) != ADDR_LINK) {
        _setupTcpListener(forwarder, listenerName, address,
                (char *)interfaceGetName(iface));
//      }
    }
  }

  interfaceSetDestroy(&set);
#endif
}

// XXX TODO
void
configurationListeners_SetupLocalIPv4(const Configuration *config,
        uint16_t port)
{
  Forwarder * forwarder = configuration_GetForwarder(config);
  address_t address = ADDRESS4_LOCALHOST(port);

  _setupUdpListener(forwarder, "lo_udp", &address, "lo");
  _setupTcpListener(forwarder, "lo_tcp", &address, "lo");
}
