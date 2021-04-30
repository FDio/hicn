#include <arpa/inet.h>  // inet_ntop
#include <netdb.h>      // ''
#include <search.h>     // tfind(), tdestroy(), twalk(), preorder...
#include <stdbool.h>
#include <stdio.h>       // perror
#include <stdlib.h>      // calloc
#include <string.h>      // memcpy
#include <sys/socket.h>  // ''
#include <sys/types.h>   // getaddrinfo
#include <unistd.h>      // close

#include "api.h"
#include "error.h"
#include "ops.h"

#define INET_MAX_ADDRSTRLEN INET6_ADDRSTRLEN

#define IF_NAMESIZE 16
#define MAX_TABLES 256

#define DEFAULT_INTERVAL 1000
#define DEFAULT_IDENTIFIER "hicn"
#define DEFAULT_SOCKET_IDENTIFIER "main"
#define LOCAL_IPV6_PREFIX "fe80"

#define LOCAL_PRIORITY 32000

extern hicn_socket_ops_t ops;

/* Configuration stored as a global variable to allow access from signal
 * handlers for instance */

static hicn_conf_t hicn_default_conf = {
    .identifier = DEFAULT_IDENTIFIER,
    //.format = HF_INET6_TCP
};

/* Global state */

struct ip_rule_state_ {
  char tun_name[IF_NAMESIZE];
  ip_prefix_t prefix;
  uint32_t table_id;
  uint8_t priority;
  uint8_t address_family;
};

struct ip_route_state_ {
  char remote_ip_address[128];  // this is to big, but it is fine for now
  uint8_t address_family;
  uint32_t table_id;
};

typedef struct ip_rule_state_ ip_rule_state;
typedef struct ip_route_state_ ip_route_state;

int punting_table_id;
uint16_t rules_counter;
uint16_t routes_counter;
static ip_rule_state rules_to_remove[MAX_TABLES];
static ip_route_state routes_to_remove[MAX_TABLES];

hicn_socket_helper_t *hicn_create() {
  int rc;

  punting_table_id = -1;
  rules_counter = 0;

  hicn_socket_helper_t *hicn = malloc(sizeof(hicn_socket_helper_t));
  if (!hicn) {
    goto ERR_MALLOC;
  }

  hicn->conf = malloc(sizeof(hicn_conf_t));
  if (hicn->conf < 0)
    goto ERR_CONF;
  memcpy(hicn->conf, &hicn_default_conf, sizeof(hicn_conf_t));

  /* Initialize socket tree to empty */
  hicn->socket_root = NULL;

  // enable forwarding globally. Per-interface forwarding will be enabled when
  // interfaces are created (TODO)
  rc = ops.enable_v6_forwarding(NULL);
  if (rc < 0) {
    goto ERR_FW;
  }

  rc = ops.enable_v4_forwarding();
  if (rc < 0) {
    goto ERR_FW;
  }

  // modify priority of table local
  /* ip -6 rule del from all prio 0 table local */
  /* ip -6 rule add from all prio 32000 table local */

  rc = ops.del_lo_prio_rule(NULL, AF_INET6, 0);
  if (rc < 0) {
    goto ERR_FW;
  }

  rc = ops.del_lo_prio_rule(NULL, AF_INET, 0);
  if (rc < 0) {
    goto ERR_FW;
  }

  rc = ops.add_lo_prio_rule(NULL, AF_INET6, LOCAL_PRIORITY);
  if (rc < 0) {
    goto ERR_FW;
  }

  rc = ops.add_lo_prio_rule(NULL, AF_INET, LOCAL_PRIORITY);
  if (rc < 0) {
    goto ERR_FW;
  }

  return hicn;

ERR_FW:
  free(hicn->conf);
ERR_CONF:
  free(hicn);
ERR_MALLOC:
  return NULL;
}

void hicn_destroy() {
  int rc;
  int ret = 0;
  uint16_t i;

  /* Restore default rules */
  printf("Restoring default configuration.\n");
  rc = ops.del_lo_prio_rule(NULL, AF_INET6, LOCAL_PRIORITY);
  if (rc < 0)
    ret = -1;

  rc = ops.del_lo_prio_rule(NULL, AF_INET, LOCAL_PRIORITY);
  if (rc < 0)
    ret = -1;

  rc = ops.add_lo_prio_rule(NULL, AF_INET6, 0);
  if (rc < 0)
    ret = -1;

  rc = ops.add_lo_prio_rule(NULL, AF_INET, 0);
  if (rc < 0)
    ret = -1;

  for (i = 0; i < rules_counter; i++) {
    if (strcmp(rules_to_remove[i].tun_name, "NONE") != 0) {
      rc = ops.del_rule(rules_to_remove[i].tun_name,
                        rules_to_remove[i].address_family,
                        rules_to_remove[i].table_id);
    } else {
      rc = ops.del_prio_rule(
          &rules_to_remove[i].prefix, rules_to_remove[i].address_family,
          rules_to_remove[i].priority, rules_to_remove[i].table_id);
    }
    if (rc < 0)
      ret = -1;
  }

  for (i = 0; i < routes_counter; i++) {
    rc = ops.del_out_route(routes_to_remove[i].remote_ip_address,
                           routes_to_remove[i].address_family,
                           routes_to_remove[i].table_id);
    if (rc < 0)
      ret = -1;
  }

  if (ret < 0)
      printf("Unexpected exit. Some state may not be deleted.\n");
}

void hicn_free(hicn_socket_helper_t *hicn) {
  hicn_destroy();
  free(hicn->conf);
  free(hicn);
}

hicn_socket_t *hicn_socket_create() {
  hicn_socket_t *socket = calloc(1, sizeof(hicn_socket_t));
  if (!socket) {
    goto ERR_SOCKET;
  }
  socket->type = HS_UNSPEC;

  return socket;

ERR_SOCKET:
  return NULL;
}

int hicn_socket_cmp(hicn_socket_t *a, hicn_socket_t *b) {
  return b->fd - a->fd;
}

ip_prefix_t *hicn_socket_get_src_ip(hicn_socket_t *socket) {
  if (socket->type != HS_CONNECTION) {
    return NULL;
  }
  return &socket->connection.tun_ip_address;
}

typedef int (*cmp_t)(const void *, const void *);

int hicn_socket_add(hicn_socket_helper_t *hicn, hicn_socket_t *socket) {
  if (!(tsearch(socket, &hicn->socket_root, (cmp_t)hicn_socket_cmp))) {
    // ERROR("Could not insert field id into index");
    return -1;
  }
  return 0;
}

hicn_socket_t *hicn_socket_find(hicn_socket_helper_t *hicn, int fd) {
  hicn_socket_t search = {
      .fd = fd,
  };
  hicn_socket_t **socket =
      tfind(&search, &hicn->socket_root, (cmp_t)hicn_socket_cmp);
  return socket ? *socket : NULL;
}

/*******************************************************************************
 * New API
 *******************************************************************************/

int hicn_set_local_endpoint(hicn_socket_t *socket, const char *local_ip_address,
                            bool allow_null) {
  int rc = HICN_SOCKET_ERROR_NONE;

  if (!local_ip_address) {
    if (!allow_null) {
      rc = HICN_SOCKET_ERROR_SOCKET_LOCAL_NULL_ADDRESS;
    }
    goto end;
  }

  /* local_ip_address should be a prefix with global scope in which to pick
   * the locator address to use as the source.
   * If we expect to pick another IP for the tun, then it needs to be of size
   * less than 128.
   */

  /* Copy the local IP address inside the connection */
  rc = ip_prefix_pton(local_ip_address, &socket->connection.tun_ip_address);
  if (rc < 0) {
    rc = HICN_SOCKET_ERROR_SOCKET_LOCAL_REPR;
    goto end;
  }

end:
  return rc;
}

int hicn_get_local_address(const ip_prefix_t *remote_address,
                           ip_prefix_t *local_address) {
  int rc = 0;
  uint32_t interface_id;
  char remote_address_str[INET_MAX_ADDRSTRLEN + 4 ];

  rc = ip_prefix_ntop_short(remote_address, remote_address_str,
                    sizeof(remote_address_str));
  if (rc < 0) {
    rc = HICN_SOCKET_ERROR_BIND_REMOTE_REPR;
    goto ERR;
  }

  rc = ops.get_output_ifid(remote_address_str, remote_address->family,
                           &interface_id);
  if (rc < 0 || interface_id == 0) {
    rc = HICN_SOCKET_ERROR_BIND_REMOTE_INTERFACE;
    goto ERR;
  }

  /* Local ip */
  rc = ops.get_ip_addr(interface_id, remote_address->family, local_address);
  if (rc < 0) {
    rc = HICN_SOCKET_ERROR_BIND_REMOTE_NETMASK;
    goto ERR;
  }

ERR:
  return rc;
}

/**
 *
 * sets socket->interface_id
 */
int hicn_set_remote_endpoint(hicn_socket_t *socket,
                             const char *remote_ip_address) {
  int af, rc = HICN_SOCKET_ERROR_NONE;
  ip_prefix_t addr;

  af = get_addr_family(remote_ip_address);
  if ((af != AF_INET6) && (af != AF_INET)) {
    return HICN_SOCKET_ERROR_INVALID_IP_ADDRESS;
  }

  /* Bind local endpoint if not done yet */
  if (ip_prefix_empty(&socket->connection.tun_ip_address)) {
    char local_ip_address[INET_MAX_ADDRSTRLEN + 4];

    /* Local interface id */
    // INFO("Getting interface_id from gateway IP address %s",
    // remote_ip_address);
    /////
    int addr_family = get_addr_family(remote_ip_address);
    if (addr_family < 0) {
      rc = addr_family;
      goto ERR;
    }

    rc = ops.get_output_ifid(remote_ip_address, (uint8_t)addr_family,
                             &socket->connection.interface_id);
    if (rc < 0 || socket->connection.interface_id == 0) {
      rc = HICN_SOCKET_ERROR_BIND_REMOTE_INTERFACE;
      goto ERR;
    }

    /* Local ip */
    rc = ops.get_ip_addr(socket->connection.interface_id, (uint8_t)addr_family,
                         &addr);
    if (rc < 0) {
      rc = HICN_SOCKET_ERROR_BIND_REMOTE_NETMASK;
      goto ERR;
    }
    /////

    /* Convert to representation format */
    rc = ip_prefix_ntop_short(&addr, local_ip_address, sizeof(local_ip_address));
    if (rc < 0) {
      rc = HICN_SOCKET_ERROR_BIND_REMOTE_REPR;
      goto ERR;
    }

    rc = hicn_set_local_endpoint(socket, local_ip_address, true);
    if (rc < 0) {
      switch (rc) {
        case HICN_SOCKET_ERROR_SOCKET_LOCAL_NULL_ADDRESS:
          rc = HICN_SOCKET_ERROR_BIND_REMOTE_LOCAL_NULL_ADDR;
          break;
        case HICN_SOCKET_ERROR_SOCKET_LOCAL_REPR:
          rc = HICN_SOCKET_ERROR_BIND_REMOTE_LOCAL_REPR;
          break;
        case HICN_SOCKET_ERROR_SOCKET_LOCAL_HEURISTIC:
          rc = HICN_SOCKET_ERROR_BIND_REMOTE_LOCAL_HEURISTIC;
          break;
        case HICN_SOCKET_ERROR_SOCKET_LOCAL_SET_TUN_IP:
          rc = HICN_SOCKET_ERROR_BIND_REMOTE_LOCAL_SET_TUN_IP;
          break;
      }
      goto ERR;
    }
  }
  return HICN_SOCKET_ERROR_NONE;

ERR:
  return rc;
}

/**
 *
 * We need at least an identifier.
 */
int hicn_socket(hicn_socket_helper_t *hicn, const char *identifier,
                const char *local_ip_address) {
  int rc;

  hicn_socket_t *socket = hicn_socket_create();
  if (!socket) {
    rc = -5;
    goto ERR_SOCKET;
  }

  ops.get_tun_name(hicn->conf->identifier, identifier, socket->tun_name);

  // register the hicn face on which to bind prefixes, create the in/out TUN
  // device
  socket->fd = ops.tun_create(socket->tun_name);
  if (socket->fd <= 0) {
    rc = -2;
    goto ERR_TUN;
  }

  // INFO("Successfully created listener on TUN device %s", socket->tun_name);

  /* Retrieve interface id */
  socket->tun_id = ops.get_ifid(socket->tun_name);
  if (socket->tun_id < 0) {
    rc = -3;
    goto ERR_TUNIFID;
  }
  // INFO("Interface id=%d", socket->tun_id);

  // WARN("Need to set offload");

  // INFO("Setting interface up");
  rc = ops.up_if(socket->tun_id);
  if (rc < 0) {
    rc = -4;
    goto ERR_UP;
  }

  /* Update state */
  rc = hicn_socket_add(hicn, socket);
  if (rc < 0) {
    rc = -5;
    goto ERR_ADD;
  }

  rc = hicn_set_local_endpoint(socket, local_ip_address, true);
  if (rc < 0) {
    rc = -6;
    goto ERR_ADJACENCY;
  }

  return socket->fd;

ERR_ADJACENCY:
ERR_ADD:
ERR_UP:
ERR_TUNIFID:
ERR_TUN:
  free(socket);
ERR_SOCKET:
  // ERR_PARAMS:
  return rc;
}

int hicn_listen(hicn_socket_helper_t *hicn, int fd, const char *prefix) {
  int rc;
  hicn_socket_t *socket = hicn_socket_find(hicn, fd);
  if (!socket) {
    return -1;
  }

  /* Check socket is not a connection */
  if (socket->type == HS_CONNECTION) {
    return -1;
  }

  rc = ops.add_in_route_s(prefix, socket->tun_id);
  if (rc < 0) {
    return rc;
  }

  ip_prefix_t ip_prefix;
  rc = ip_prefix_pton(prefix, &ip_prefix);
  if (rc < 0) {
    return rc;
  }

  // ip -6 rule add from b001::/16 prio 0 table 100
  socket->connection.table_id =
      socket->tun_id % MAX_TABLES;  // this table should be unused

  if (punting_table_id == -1) punting_table_id = socket->connection.table_id;

  rc = ops.add_prio_rule(&ip_prefix, ip_prefix.family, 0,
                         socket->connection.table_id);
  if (rc < 0) {
    return rc;
  }

  strcpy(rules_to_remove[rules_counter].tun_name, "NONE");

  rules_to_remove[rules_counter].prefix = ip_prefix;
  rules_to_remove[rules_counter].address_family = ip_prefix.family;
  rules_to_remove[rules_counter].table_id = socket->connection.table_id;
  rules_to_remove[rules_counter].priority = 0;
  ++rules_counter;

  /* Update socket upon success */
  socket->type = HS_LISTENER;

  return 0;
}

/**
 *
 * We can pass all adjacency parameters but identifier
 */
int hicn_bind(hicn_socket_helper_t *hicn, int fd,
              const char *remote_ip_address) {
  // uint32_t interface_id;
  int rc = HICN_SOCKET_ERROR_NONE;

  hicn_socket_t *socket = hicn_socket_find(hicn, fd);
  if (!socket) {
    rc = HICN_SOCKET_ERROR_BIND_SOCKET_NOT_FOUND;
    goto ERR;
  }

  /* We allow reuse */
  if (socket->type == HS_CONNECTION) return rc;

  /* Check socket is not a connection */
  if (socket->type != HS_UNSPEC) {
    rc = HICN_SOCKET_ERROR_BIND_SOCKET_ALREADY_BOUND;
    goto ERR;
  }
  socket->type = HS_CONNECTION;

  // each connection is associated a table id, let's take it equal to the
  // tun ID by default (% MAX_TABLES, assuming TUN IDs do not overlap modulo
  // 256...).
  socket->connection.table_id =
      socket->tun_id % MAX_TABLES;  // interface_id; // ops.get_free_table_id();

  rc = hicn_set_remote_endpoint(socket, remote_ip_address);
  if (rc < 0) {
    goto ERR;
  }

  // rule
  // ip -6 rule from all iif eth0 lookup 200
  // INFO("Adding output rule for %s in table %d", socket->tun_name,
  //        socket->connection.table_id);
  int addr_family = get_addr_family(remote_ip_address);
  if (addr_family < 0) {
    rc = addr_family;
    goto ERR;
  }

  rc = ops.add_rule(socket->tun_name, (uint8_t)addr_family,
                    socket->connection.table_id);
  if (rc < 0) {
    rc = HICN_SOCKET_ERROR_BIND_RULE;
    goto ERR;
  }

  strcpy(rules_to_remove[rules_counter].tun_name, socket->tun_name);
  rules_to_remove[rules_counter].address_family = addr_family;
  rules_to_remove[rules_counter].table_id = socket->connection.table_id;
  ++rules_counter;

  // route
  // ip -6 route add default via 2002::2 table 28
  // INFO("Adding output route in table %d via gateway %s",
  // socket->connection.table_id,
  //        remote_ip_address);

  // if the address is an IPv6 and start with fe80 we need to specify the device
  // in the route
  u32 default_interface = ~0;
  if (addr_family == AF_INET6 && strncmp(LOCAL_IPV6_PREFIX, remote_ip_address,
                                         strlen(LOCAL_IPV6_PREFIX)) == 0) {
    rc = ops.get_output_ifid(remote_ip_address, (uint8_t)addr_family,
                             &default_interface);
    if (rc < 0) {
      goto ERR;
    }
  }

  rc = ops.add_out_route(remote_ip_address, (uint8_t)addr_family,
                         socket->connection.table_id, default_interface);
  if (rc < 0) {
    rc = HICN_SOCKET_ERROR_BIND_ROUTE;
    goto ERR;
  }

  strcpy(routes_to_remove[routes_counter].remote_ip_address, remote_ip_address);
  routes_to_remove[routes_counter].table_id = socket->connection.table_id;
  routes_to_remove[routes_counter].address_family = (uint8_t)addr_family;
  ++routes_counter;

  // add route for data
  // ip -6 route add 0:1::/64 dev hicn-if0 table 100
  // this routes are deleted by removing the tun interfaces

  if (punting_table_id == -1) {
    // the punting_table_id was not initialized beacause no main-tun was created
    // we use as an id (socket->tun_id - 1) % MAX_TABLES, so that we will hava a
    // collision only after 255 new interfaces
    punting_table_id = (socket->tun_id - 1) % MAX_TABLES;
  }
  rc = ops.add_in_route_table(&socket->connection.tun_ip_address,
                              socket->tun_id, punting_table_id);
  if (rc < 0) {
    rc = HICN_SOCKET_ERROR_BIND_ROUTE;
    goto ERR;
  }

ERR:
  return rc;
}
