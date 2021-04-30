#ifndef HICN_SOCKET_OPS_H
#define HICN_SOCKET_OPS_H

#include <hicn/hicn.h>
#include <stdint.h>

typedef struct {
  char *arch;
  int (*tun_create)(char *name);
  int (*get_tun_name)(const char *prefix, const char *identifier,
                      char *tun_name);
  int (*enable_v6_forwarding)(char *interface_name);
  int (*enable_v4_forwarding)();
  int (*enable_ndp_proxy)();

  uint32_t (*get_ifid)(const char *ifname);
  int (*get_output_ifid)(const char *ip_address, uint8_t address_family,
                         uint32_t *interface_id);
  int (*get_ip_addr)(uint32_t interface_id, uint8_t address_family,
                     ip_prefix_t *ip_address);
  int (*set_ip_addr)(uint32_t interface_id, ip_prefix_t *ip_address);
  int (*up_if)(uint32_t interface_id);
  int (*add_in_route_table)(const ip_prefix_t *prefix,
                            const uint32_t interface_id,
                            const uint8_t table_id);
  int (*add_in_route_table_s)(const char *prefix, const uint32_t interface_id,
                              const uint8_t table_id);
  int (*add_in_route_s)(const char *prefix, const uint32_t interface_id);
  int (*add_out_route)(const char *gateway, const uint8_t address_family,
                       const uint8_t table_id, int default_route);
  int (*del_out_route)(const char *gateway, const uint8_t address_family,
                       const uint8_t table_id);
  int (*del_lo_route)(const ip_prefix_t *ip_address);
  int (*add_rule)(const char *interface_name, const uint8_t address_family,
                  const uint8_t table_id);
  int (*del_rule)(const char *interface_name, const uint8_t address_family,
                  const uint8_t table_id);
  int (*add_neigh_proxy)(const ip_prefix_t *ip_address,
                         const uint32_t interface_id);
  int (*add_prio_rule)(const ip_prefix_t *ip_address,
                       const uint8_t address_family, const uint32_t priority,
                       const uint8_t table_id);
  int (*add_lo_prio_rule)(const ip_prefix_t *ip_address,
                          const uint8_t address_family,
                          const uint32_t priority);
  int (*del_prio_rule)(const ip_prefix_t *ip_address,
                       const uint8_t address_family, const uint32_t priority,
                       const uint8_t table_id);
  int (*del_lo_prio_rule)(const ip_prefix_t *ip_address,
                          const uint8_t address_family,
                          const uint32_t priority);
} hicn_socket_ops_t;

#endif /* HICN_SOCKET_OPS_H */
