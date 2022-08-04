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

/**
 * \file interfaces/bonjour/bonjour.c
 * \brief Implementation of Bonjour interface
 *
 * TODO:
 *  - concurrent queries
 *  - interface binding
 */

#include <hicn/facemgr.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>
#include <hicn/util/sstrncpy.h>

#include "../../common.h"
#include "../../interface.h"
#include "mdns/mdns.h"

#include "bonjour.h"

#define DEFAULT_BUFFER_SIZE 2048
#define SERVICE_STRING_SIZE 256

#define DEFAULT_SERVICE_NAME "hicn"
#define DEFAULT_SERVICE_PROTOCOL "udp"
#define DEFAULT_SERVICE_DOMAIN "local"

typedef struct {
  bonjour_cfg_t cfg;
  int sock;
  size_t buffer_size;
  void* buffer;

  /* The face being resolved, non-NULL values indicate interface is busy... */
  face_t* face;
} bj_data_t;

int bj_initialize(interface_t* interface, void* cfg) {
  bj_data_t* data = malloc(sizeof(bj_data_t));
  if (!data) goto ERR_MALLOC;
  interface->data = data;

  if (cfg) {
#ifndef __linux__
    if (cfg->netdevice)
      WARN("Binding to interface is (currently) only supported on Linux");
#endif /* ! __linux__ */
    data->cfg = *(bonjour_cfg_t*)cfg;
  } else {
    memset(&data->cfg, 0, sizeof(bonjour_cfg_t));
  }

  if (!data->cfg.service_name) data->cfg.service_name = DEFAULT_SERVICE_NAME;

  if (!data->cfg.service_protocol)
    data->cfg.service_protocol = DEFAULT_SERVICE_PROTOCOL;

  if (!data->cfg.service_domain)
    data->cfg.service_domain = DEFAULT_SERVICE_DOMAIN;

  data->sock = mdns_socket_open_ipv4();
  if (data->sock < 0) {
    printf("Failed to open socket: %s\n", strerror(errno));
    goto ERR_SOCK;
  }

  /* Netdevice configuration */
#ifdef __linux__
#ifndef __ANDROID__
  if (IS_VALID_NETDEVICE(data->cfg.netdevice)) {
    int rc = setsockopt(data->sock, SOL_SOCKET, SO_BINDTODEVICE,
                        &data->cfg.netdevice.name,
                        strnlen_s(data->cfg.netdevice.name, IFNAMSIZ));
    if (rc == -1) {
      ERROR("setsockopt");
      goto ERR_SOCK_OPT;
    }
  }
#endif
#endif /* __linux__ */

  data->buffer_size = DEFAULT_BUFFER_SIZE;
  data->buffer = malloc(data->buffer_size);
  if (!data->buffer) goto ERR_BUFFER;

#ifdef _WIN32
  WORD versionWanted = MAKEWORD(1, 1);
  WSADATA wsaData;
  WSAStartup(versionWanted, &wsaData);
#endif

  if (interface_register_fd(interface, data->sock, NULL) < 0) {
    ERROR("[bj_initialize] Error registering fd");
    goto ERR_FD;
  }

  return 0;

ERR_FD:
  free(data->buffer);
ERR_BUFFER:
#ifndef __ANDROID__
ERR_SOCK_OPT:
#endif
  mdns_socket_close(data->sock);
#ifdef _WIN32
  WSACleanup();
#endif
ERR_SOCK:
  free(data);
ERR_MALLOC:
  return -1;
}

/*
 * We reuse the callback to be triggered upon external events
 * TODO: move to a cleaner interface architecture later...
 */
int bj_on_event(interface_t* interface, facelet_t* facelet) {
  bj_data_t* data = (bj_data_t*)interface->data;

  /*
  printf("Sending DNS-SD discovery\n");
  if (mdns_discovery_send(sock)) {
          printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
          goto quit;
  }

  printf("Reading DNS-SD replies\n");
  for (int i = 0; i < 10; ++i) {
          records = mdns_discovery_recv(sock, buffer, capacity, callback,
                                        user_data);
          sleep(1);
  }
  */

  DEBUG("Sending mDNS query");
  char service_string[SERVICE_STRING_SIZE];

  int rc = snprintf(service_string, SERVICE_STRING_SIZE, "_%s._%s.%s.",
                    data->cfg.service_name, data->cfg.service_protocol,
                    data->cfg.service_domain);
  if (rc < 0)
    ;  // error
  else if (rc >= SERVICE_STRING_SIZE)
    ;  // truncated

  if (mdns_query_send(data->sock, MDNS_RECORDTYPE_PTR, service_string,
                      strnlen_s(service_string, SERVICE_STRING_SIZE),
                      data->buffer, data->buffer_size)) {
    printf("Failed to send mDNS query: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

static char addrbuffer[64];
static char namebuffer[256];
static mdns_record_txt_t txtbuffer[128];

static mdns_string_t ipv4_address_to_string(char* buffer, size_t capacity,
                                            const struct sockaddr_in* addr) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  int ret = getnameinfo((const struct sockaddr*)addr,
                        sizeof(struct sockaddr_in), host, NI_MAXHOST, service,
                        NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
  int len = 0;
  if (ret == 0) {
    if (addr->sin_port != 0)
      len = snprintf(buffer, capacity, "%s:%s", host, service);
    else
      len = snprintf(buffer, capacity, "%s", host);
  }
  if (len >= (int)capacity) len = (int)capacity - 1;
  mdns_string_t str = {buffer, len};
  return str;
}

static mdns_string_t ipv6_address_to_string(char* buffer, size_t capacity,
                                            const struct sockaddr_in6* addr) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  int ret = getnameinfo((const struct sockaddr*)addr,
                        sizeof(struct sockaddr_in6), host, NI_MAXHOST, service,
                        NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
  int len = 0;
  if (ret == 0) {
    if (addr->sin6_port != 0)
      len = snprintf(buffer, capacity, "[%s]:%s", host, service);
    else
      len = snprintf(buffer, capacity, "%s", host);
  }
  if (len >= (int)capacity) len = (int)capacity - 1;
  mdns_string_t str = {buffer, len};
  return str;
}

static mdns_string_t hicn_ip_address_to_string(char* buffer, size_t capacity,
                                               const struct sockaddr* addr) {
  if (addr->sa_family == AF_INET6)
    return ipv6_address_to_string(buffer, capacity,
                                  (const struct sockaddr_in6*)addr);
  return ipv4_address_to_string(buffer, capacity,
                                (const struct sockaddr_in*)addr);
}

int hicn_ip_address_set_sockaddr(hicn_ip_address_t* ip_address,
                                 struct sockaddr* sa) {
  switch (sa->sa_family) {
    case AF_INET:
      ip_address->v4.as_inaddr = ((struct sockaddr_in*)sa)->sin_addr;
      break;
    case AF_INET6:
      ip_address->v6.as_in6addr = ((struct sockaddr_in6*)sa)->sin6_addr;
      break;
    default:
      return -1;
  }

  return 0;
}

static int callback(const struct sockaddr* from, mdns_entry_type_t entry,
                    uint16_t type, uint16_t rclass, uint32_t ttl,
                    const void* data, size_t size, size_t offset, size_t length,
                    void* user_data) {
  interface_t* interface = (interface_t*)user_data;
  bj_data_t* bj_data = (bj_data_t*)interface->data;

  struct sockaddr_storage addr;

  mdns_string_t fromaddrstr =
      hicn_ip_address_to_string(addrbuffer, sizeof(addrbuffer), from);
  const char* entrytype =
      (entry == MDNS_ENTRYTYPE_ANSWER)
          ? "answer"
          : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");

  switch (type) {
    case MDNS_RECORDTYPE_A: {
      hicn_ip_address_t ip_address;
      mdns_record_parse_a(data, size, offset, length,
                          (struct sockaddr_in*)&addr);
      hicn_ip_address_set_sockaddr(&ip_address, (struct sockaddr*)&addr);

      mdns_string_t addrstr = ipv4_address_to_string(
          namebuffer, sizeof(namebuffer), (struct sockaddr_in*)&addr);
      DEBUG("%.*s : %s A %.*s", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
            MDNS_STRING_FORMAT(addrstr));

      facelet_t* facelet = facelet_create();
      facelet_set_netdevice(facelet, bj_data->cfg.netdevice);
      facelet_set_family(facelet, AF_INET);
      facelet_set_remote_addr(facelet, ip_address);
      // facelet_set_remote_port(facelet, ((struct
      // sockaddr_in*)&addr)->sin_port);

      facelet_set_event(facelet, FACELET_EVENT_UPDATE);
      interface_raise_event(interface, facelet);
      break;
    }

    case MDNS_RECORDTYPE_AAAA: {
      hicn_ip_address_t ip_address;
      mdns_record_parse_aaaa(data, size, offset, length,
                             (struct sockaddr_in6*)&addr);
      hicn_ip_address_set_sockaddr(&ip_address, (struct sockaddr*)&addr);

      mdns_string_t addrstr = ipv6_address_to_string(
          namebuffer, sizeof(namebuffer), (struct sockaddr_in6*)&addr);
      DEBUG("%.*s : %s AAAA %.*s", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
            MDNS_STRING_FORMAT(addrstr));

      facelet_t* facelet = facelet_create();
      facelet_set_netdevice(facelet, bj_data->cfg.netdevice);
      facelet_set_family(facelet, AF_INET6);
      facelet_set_remote_addr(facelet, ip_address);
      // facelet_set_remote_port(facelet, ((struct
      // sockaddr_in6*)&addr)->sin6_port);

      facelet_set_event(facelet, FACELET_EVENT_UPDATE);
      interface_raise_event(interface, facelet);
      break;
    }

    case MDNS_RECORDTYPE_SRV: /* same port for both v4 and v6 */
    {
      mdns_record_srv_t srv = mdns_record_parse_srv(
          data, size, offset, length, namebuffer, sizeof(namebuffer));

      DEBUG("%.*s : %s SRV %.*s priority %d weight %d port %d",
            MDNS_STRING_FORMAT(fromaddrstr), entrytype,
            MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);

      /* We raise both v4 and v6
       *
       * Unless we choose whether we query A and/or AAAA, this might leave
       * us with an unused pending facelet, eg. we might not have an IPv6
       * but we raise an IPv6 bonjour event...
       */

      facelet_t* facelet = facelet_create();
      facelet_set_netdevice(facelet, bj_data->cfg.netdevice);
      facelet_set_family(facelet, AF_INET);
      facelet_set_remote_port(facelet, srv.port);

      facelet_set_event(facelet, FACELET_EVENT_UPDATE);
      interface_raise_event(interface, facelet);

      facelet = facelet_create();
      facelet_set_netdevice(facelet, bj_data->cfg.netdevice);
      facelet_set_family(facelet, AF_INET6);
      facelet_set_remote_port(facelet, srv.port);

      facelet_set_event(facelet, FACELET_EVENT_UPDATE);
      interface_raise_event(interface, facelet);
      break;
    }

    case MDNS_RECORDTYPE_PTR: {
      mdns_string_t namestr = mdns_record_parse_ptr(
          data, size, offset, length, namebuffer, sizeof(namebuffer));
      DEBUG("%.*s : %s PTR %.*s type %u rclass 0x%x ttl %u length %d",
            MDNS_STRING_FORMAT(fromaddrstr), entrytype,
            MDNS_STRING_FORMAT(namestr), type, rclass, ttl, (int)length);
      break;
    }

    case MDNS_RECORDTYPE_TXT: {
      size_t parsed =
          mdns_record_parse_txt(data, size, offset, length, txtbuffer,
                                sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
      for (size_t itxt = 0; itxt < parsed; ++itxt) {
        if (txtbuffer[itxt].value.length) {
          DEBUG("%.*s : %s TXT %.*s = %.*s", MDNS_STRING_FORMAT(fromaddrstr),
                entrytype, MDNS_STRING_FORMAT(txtbuffer[itxt].key),
                MDNS_STRING_FORMAT(txtbuffer[itxt].value));
        } else {
          DEBUG("%.*s : %s TXT %.*s", MDNS_STRING_FORMAT(fromaddrstr),
                entrytype, MDNS_STRING_FORMAT(txtbuffer[itxt].key));
        }
      }
      break;
    }

    default:
      /* Silently ignore the received record */
      DEBUG("%.*s : %s type %u rclass 0x%x ttl %u length %d",
            MDNS_STRING_FORMAT(fromaddrstr), entrytype, type, rclass, ttl,
            (int)length);
      return 0;
  }
  return 0;
}

/*
 * The fact we use a single fd does not allow us to get user_data associated to
 * the query.
 */
int bj_callback(interface_t* interface, int fd, void* unused) {
  bj_data_t* data = (bj_data_t*)interface->data;
  DEBUG("Got an mDNS reply");
  /* size_t records = */ mdns_query_recv(
      data->sock, data->buffer, data->buffer_size, callback, interface, 1);

  return 0;
}

int bj_finalize(interface_t* interface) {
  bj_data_t* data = (bj_data_t*)interface->data;

  free(data->buffer);
  mdns_socket_close(data->sock);

#ifdef _WIN32
  WSACleanup();
#endif

  return 0;
}

const interface_ops_t bonjour_ops = {
    .type = "bonjour",
    .initialize = bj_initialize,
    .on_event = bj_on_event,
    .callback = bj_callback,
    .finalize = bj_finalize,
    //  .on_event = NULL,
};
