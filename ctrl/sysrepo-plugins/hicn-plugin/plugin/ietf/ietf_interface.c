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

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/xpath.h>
#include <vnet/interface.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vapi/interface.api.vapi.h>

#include "ietf_interface.h"
#include "../hicn_vpp_comm.h"

DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON;

typedef struct hicn_interface_ {
  u32 sw_if_index;
  char interface_name[VPP_INTFC_NAME_LEN];
  u8 l2_address[VPP_MAC_ADDRESS_LEN];
  u64 link_speed;
  u32 flags;
  u16 link_mtu;
  u8 admin_up_down;
  u8 link_up_down;
} hicnIntfc;

typedef struct _ietf_sw_interface_dump_ctx {
  u8 last_called;
  int num_ifs;
  int capacity;
  hicnIntfc *intfcArray;
} ietf_sw_interface_dump_ctx;

static i32 ietf_setInterfaceFlags(u32 sw_if_index, u8 admin_up_down);
static i32 ietf_interface_name2index(const char *name, u32 *if_index);
static i32 ietf_interface_add_del_addr(u32 sw_if_index, u8 is_add, u8 is_ipv6,
                                       u8 del_all, u8 address_length,
                                       u8 address[VPP_IP6_ADDRESS_LEN]);
static int ietf_initSwInterfaceDumpCTX(ietf_sw_interface_dump_ctx *dctx);
static int ietf_freeSwInterfaceDumpCTX(ietf_sw_interface_dump_ctx *dctx);

/**
 * @brief Helper function for converting netmask into prefix length.
 */
static uint8_t netmask_to_prefix(const char *netmask) {
  in_addr_t n = 0;
  uint8_t i = 0;

  inet_pton(AF_INET, netmask, &n);

  while (n > 0) {
    n = n >> 1;
    i++;
  }

  return i;
}

/**
 * @brief Helper function for converting IPv4/IPv6 address string into binary
 * representation.
 */
static int ip_addr_str_to_binary(const char *ip_address_str,
                                 uint8_t *ip_address_bin, bool is_ipv6) {
  struct in6_addr addr6 = {
      0,
  };
  struct in_addr addr4 = {
      0,
  };
  int ret = 0;

  if (is_ipv6) {
    ret = inet_pton(AF_INET6, ip_address_str, &(addr6));
    if (1 == ret) {
      memcpy(ip_address_bin, &addr6, sizeof(addr6));
    }
  } else {
    ret = inet_pton(AF_INET, ip_address_str, &(addr4));
    if (1 == ret) {
      memcpy(ip_address_bin, &addr4, sizeof(addr4));
    }
  }

  return ret;
}

/**
 * @brief Enable or disable given interface.
 */
static int interface_enable_disable(const char *if_name, bool enable) {
  uint32_t if_index = ~0;
  int rc = 0;

  /* get interface index */
  rc = ietf_interface_name2index(if_name, &if_index);
  if (0 != rc) {
    SRP_LOG_ERRMSG("Invalid interface name");
    return SR_ERR_INVAL_ARG;
  }

  /* enable/disable interface */
  rc = ietf_setInterfaceFlags(if_index, (uint8_t)enable);
  if (0 != rc) {
    SRP_LOG_ERRMSG("Error by processing of the sw_interface_set_flags request");
    return SR_ERR_OPERATION_FAILED;
  } else {
    return SR_ERR_OK;
  }
}

vapi_error_e call_sw_interface_add_del_address(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_sw_interface_add_del_address_reply *reply) {
  if (!reply->retval) {
    SRP_LOG_DBGMSG("Successfully done");
    return VAPI_OK;
  } else
    return VAPI_EUSER;
}

vapi_error_e call_sw_interface_set_flags(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_sw_interface_set_flags_reply *reply) {
  if (!reply->retval) {
    SRP_LOG_DBGMSG("Successfully done");
    return VAPI_OK;
  } else
    return VAPI_EUSER;
}

/**
 * @brief Callback to be called by any config change of
 * "/ietf-interfaces:interfaces/interface/enabled" leaf.
 */
static int ietf_interface_enable_disable_cb(sr_session_ctx_t *session,
                                            const char *module_name,
                                            const char *xpath, sr_event_t event,
                                            uint32_t request_id,
                                            void *private_data) {
  char *if_name = NULL;
  sr_change_iter_t *iter = NULL;
  sr_change_oper_t op = SR_OP_CREATED;
  sr_val_t *old_val = NULL;
  sr_val_t *new_val = NULL;
  sr_xpath_ctx_t xpath_ctx = {
      0,
  };
  int rc = SR_ERR_OK, op_rc = SR_ERR_OK;

  /* no-op for apply, we only care about SR_EV_ENABLED, SR_EV_VERIFY,
   * SR_EV_ABORT */
  if (SR_EV_DONE == event) {
    return SR_ERR_OK;
  }

  /* get changes iterator */
  rc = sr_get_changes_iter(session, xpath, &iter);
  if (SR_ERR_OK != rc) {
    SRP_LOG_ERRMSG("Unable to retrieve change iterator");
    return rc;
  }

  /* iterate over all changes */
  while ((SR_ERR_OK == op_rc || event == SR_EV_ABORT) &&
         (SR_ERR_OK ==
          (rc = sr_get_change_next(session, iter, &op, &old_val, &new_val)))) {
    SRP_LOG_DBGMSG("A change detected");
    if_name = sr_xpath_key_value(new_val ? new_val->xpath : old_val->xpath,
                                 "interface", "name", &xpath_ctx);
    switch (op) {
      case SR_OP_CREATED:
      case SR_OP_MODIFIED:
        op_rc = interface_enable_disable(if_name, new_val->data.bool_val);
        break;
      case SR_OP_DELETED:
        op_rc = interface_enable_disable(if_name, false /* !enable */);
        break;
      default:
        break;
    }
    sr_xpath_recover(&xpath_ctx);
    if (SR_ERR_INVAL_ARG == op_rc) {
      sr_set_error(session, "Invalid interface name.",
                   new_val ? new_val->xpath : old_val->xpath);
    }
    sr_free_val(old_val);
    sr_free_val(new_val);
  }
  sr_free_change_iter(iter);

  return op_rc;
}

/**
 * @brief Add or remove IPv4/IPv6 address to/from an interface.
 */
static int interface_ipv46_config_add_remove(const char *if_name, uint8_t *addr,
                                             uint8_t prefix, bool is_ipv6,
                                             bool add) {
  uint32_t if_index = ~0;
  int rc = 0;

  /* get interface index */
  rc = ietf_interface_name2index(if_name, &if_index);
  if (0 != rc) {
    SRP_LOG_ERRMSG("Invalid interface name");
    return SR_ERR_INVAL_ARG;
  }

  /* add del addr */
  rc = ietf_interface_add_del_addr(if_index, (uint8_t)add, (uint8_t)is_ipv6, 0,
                                   prefix, addr);
  if (0 != rc) {
    SRP_LOG_ERRMSG("Error by processing of the sw_interface_set_flags request");
    return SR_ERR_OPERATION_FAILED;
  } else {
    return SR_ERR_OK;
  }
}
int ietf_initSwInterfaceDumpCTX(ietf_sw_interface_dump_ctx *dctx) {
  if (dctx == NULL) return -1;

  dctx->intfcArray = NULL;
  dctx->last_called = false;
  dctx->capacity = 0;
  dctx->num_ifs = 0;
  return 0;
}
int ietf_freeSwInterfaceDumpCTX(ietf_sw_interface_dump_ctx *dctx) {
  if (dctx == NULL) return -1;

  if (dctx->intfcArray != NULL) {
    free(dctx->intfcArray);
  }

  return ietf_initSwInterfaceDumpCTX(dctx);
}
vapi_error_e ietf_sw_interface_dump_cb(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_sw_interface_details *reply) {
  ietf_sw_interface_dump_ctx *dctx = callback_ctx;
  if (is_last) {
    dctx->last_called = true;
  } else {
    if (dctx->capacity == 0 && dctx->intfcArray == NULL) {
      dctx->capacity = 10;
      dctx->intfcArray =
          (hicnIntfc *)malloc(sizeof(hicnIntfc) * dctx->capacity);
    }
    if (dctx->num_ifs >= dctx->capacity - 1) {
      dctx->capacity += 10;
      dctx->intfcArray = (hicnIntfc *)realloc(
          dctx->intfcArray, sizeof(hicnIntfc) * dctx->capacity);
    }

    hicnIntfc *thisIntfc = &dctx->intfcArray[dctx->num_ifs];

    thisIntfc->sw_if_index = reply->sw_if_index;
    memcpy(thisIntfc->interface_name, reply->interface_name,
           VPP_INTFC_NAME_LEN);
    memcpy(thisIntfc->l2_address, reply->l2_address, VPP_MAC_ADDRESS_LEN);
    // thisIntfc->link_speed = reply->link_speed;
#define ONE_MEGABIT (uint64_t)1000000
    switch (reply->link_speed << VNET_HW_INTERFACE_FLAG_SPEED_SHIFT) {
      default:
        thisIntfc->link_speed = 0;
        break;
    }

    thisIntfc->link_mtu = reply->link_mtu;
    thisIntfc->flags = reply->flags;

    dctx->num_ifs += 1;
  }
  return VAPI_OK;
}

static i32 ietf_interface_name2index(const char *name, u32 *if_index) {
  ARG_CHECK2(-1, name, if_index);

  i32 ret = -1;
  ietf_sw_interface_dump_ctx dctx = {false, 0, 0, 0};
  vapi_msg_sw_interface_dump *dump;
  vapi_error_e rv;
  dctx.last_called = false;

  dump = vapi_alloc_sw_interface_dump(g_vapi_ctx_instance);
  dump->payload.name_filter_valid = true;
  memcpy(&dump->payload.name_filter, name, sizeof(dump->payload.name_filter));

  while (VAPI_EAGAIN ==
         (rv = vapi_sw_interface_dump(g_vapi_ctx_instance, dump,
                                      ietf_sw_interface_dump_cb, &dctx)))
    ;

  int i = 0;
  for (; i < dctx.num_ifs; ++i) {
    if (strcmp(dctx.intfcArray[i].interface_name, name) == 0) {
      *if_index = dctx.intfcArray[i].sw_if_index;
      ret = 0;
      break;
    }
  }
  ietf_freeSwInterfaceDumpCTX(&dctx);

  return ret;
}

i32 ietf_interface_add_del_addr(u32 sw_if_index, u8 is_add, u8 is_ipv6,
                                u8 del_all, u8 address_length,
                                u8 address[VPP_IP6_ADDRESS_LEN]) {
  i32 ret = -1;
  vapi_msg_sw_interface_add_del_address *msg =
      vapi_alloc_sw_interface_add_del_address(g_vapi_ctx_instance);
  msg->payload.sw_if_index = sw_if_index;
  msg->payload.is_add = is_add;
  msg->payload.prefix.address.af = is_ipv6 ? ADDRESS_IP6 : ADDRESS_IP4;
  msg->payload.del_all = del_all;
  msg->payload.prefix.len = address_length;
  memcpy(msg->payload.prefix.address.un.ip6, address, VPP_IP6_ADDRESS_LEN);

  if (vapi_sw_interface_add_del_address(g_vapi_ctx_instance, msg,
                                        call_sw_interface_add_del_address,
                                        NULL) != VAPI_OK) {
    SRP_LOG_DBGMSG("Operation failed");
    return SR_ERR_OPERATION_FAILED;
  }

  return ret;
}

i32 ietf_setInterfaceFlags(u32 sw_if_index, u8 admin_up_down) {
  i32 ret = -1;
  vapi_msg_sw_interface_set_flags *msg =
      vapi_alloc_sw_interface_set_flags(g_vapi_ctx_instance);
  msg->payload.sw_if_index = sw_if_index;
  msg->payload.flags = admin_up_down ? IF_STATUS_API_FLAG_ADMIN_UP : 0;

  if (vapi_sw_interface_set_flags(g_vapi_ctx_instance, msg,
                                  call_sw_interface_set_flags,
                                  NULL) != VAPI_OK) {
    SRP_LOG_DBGMSG("Operation failed");
    return SR_ERR_OPERATION_FAILED;
  }

  return ret;
}

/**
 * @brief Modify existing IPv4/IPv6 config on an interface.
 */
static int interface_ipv46_config_modify(sr_session_ctx_t *session,
                                         const char *if_name, sr_val_t *old_val,
                                         sr_val_t *new_val, bool is_ipv6) {
  sr_xpath_ctx_t xpath_ctx = {
      0,
  };
  char *addr_str = NULL;
  uint8_t addr[16] = {
      0,
  };
  uint8_t prefix = 0;
  int rc = SR_ERR_OK;

  SRP_LOG_DBGMSG("Updating IP config on interface");

  /* get old config to be deleted */
  if (SR_UINT8_T == old_val->type) {
    prefix = old_val->data.uint8_val;
  } else if (SR_STRING_T == old_val->type) {
    prefix = netmask_to_prefix(old_val->data.string_val);
  } else {
    return SR_ERR_INVAL_ARG;
  }
  addr_str =
      sr_xpath_key_value((char *)old_val->xpath, "address", "ip", &xpath_ctx);
  ip_addr_str_to_binary(addr_str, addr, is_ipv6);
  sr_xpath_recover(&xpath_ctx);

  /* delete old IP config */
  rc = interface_ipv46_config_add_remove(if_name, addr, prefix, is_ipv6,
                                         false /* remove */);
  if (SR_ERR_OK != rc) {
    SRP_LOG_ERRMSG("Unable to remove old IP address config");
    return rc;
  }

  /* update the config with the new value */
  if (sr_xpath_node_name_eq(new_val->xpath, "prefix-length")) {
    prefix = new_val->data.uint8_val;
  } else if (sr_xpath_node_name_eq(new_val->xpath, "netmask")) {
    prefix = netmask_to_prefix(new_val->data.string_val);
  }

  /* set new IP config */
  rc = interface_ipv46_config_add_remove(if_name, addr, prefix, is_ipv6,
                                         true /* add */);
  if (SR_ERR_OK != rc) {
    SRP_LOG_ERRMSG("Unable to remove old IP address config");
    return rc;
  }

  return rc;
}

/**
 * @brief Callback to be called by any config change in subtrees
 * "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address" or
 * "/ietf-interfaces:interfaces/interface/ietf-ip:ipv6/address".
 */
static int ietf_interface_ipv46_address_change_cb(
    sr_session_ctx_t *session, const char *module_name, const char *xpath,
    sr_event_t event, uint32_t request_id, void *private_data) {
  sr_change_iter_t *iter = NULL;
  sr_change_oper_t op = SR_OP_CREATED;
  sr_val_t *old_val = NULL;
  sr_val_t *new_val = NULL;
  sr_xpath_ctx_t xpath_ctx = {0};
  bool is_ipv6 = false, has_addr = false, has_prefix = false;
  uint8_t addr[16] = {
      0,
  };
  uint8_t prefix = 0;
  char *node_name = NULL, *if_name = NULL;
  int rc = SR_ERR_OK, op_rc = SR_ERR_OK;

  /* no-op for apply, we only care about SR_EV_ENABLED, SR_EV_VERIFY,
   * SR_EV_ABORT */
  if (SR_EV_DONE == event) {
    return SR_ERR_OK;
  }

  /* check whether we are handling ipv4 or ipv6 config */
  node_name = sr_xpath_node_idx((char *)xpath, 2, &xpath_ctx);
  if (NULL != node_name && 0 == strcmp(node_name, "ipv6")) {
    is_ipv6 = true;
  }
  sr_xpath_recover(&xpath_ctx);

  /* get changes iterator */
  rc = sr_get_changes_iter(session, xpath, &iter);
  if (SR_ERR_OK != rc) {
    // SRP_LOG_ERR("Unable to retrieve change iterator: %s", sr_strerror(rc));
    return rc;
  }

  /* iterate over all changes */
  while ((SR_ERR_OK == op_rc || event == SR_EV_ABORT) &&
         (SR_ERR_OK ==
          (rc = sr_get_change_next(session, iter, &op, &old_val, &new_val)))) {
    if_name =
        strdup(sr_xpath_key_value(new_val ? new_val->xpath : old_val->xpath,
                                  "interface", "name", &xpath_ctx));
    sr_xpath_recover(&xpath_ctx);

    switch (op) {
      case SR_OP_CREATED:
        if (SR_LIST_T == new_val->type) {
          /* create on list item - reset state vars */
          has_addr = has_prefix = false;
        } else {
          if (sr_xpath_node_name_eq(new_val->xpath, "ip")) {
            ip_addr_str_to_binary(new_val->data.string_val, addr, is_ipv6);
            has_addr = true;
          } else if (sr_xpath_node_name_eq(new_val->xpath, "prefix-length")) {
            prefix = new_val->data.uint8_val;
            has_prefix = true;
          } else if (sr_xpath_node_name_eq(new_val->xpath, "netmask")) {
            prefix = netmask_to_prefix(new_val->data.string_val);
            has_prefix = true;
          }
          if (has_addr && has_prefix) {
            op_rc = interface_ipv46_config_add_remove(if_name, addr, prefix,
                                                      is_ipv6, true /* add */);
          }
        }
        break;
      case SR_OP_MODIFIED:
        op_rc = interface_ipv46_config_modify(session, if_name, old_val,
                                              new_val, is_ipv6);
        break;
      case SR_OP_DELETED:
        if (SR_LIST_T == old_val->type) {
          /* delete on list item - reset state vars */
          has_addr = has_prefix = false;
        } else {
          if (sr_xpath_node_name_eq(old_val->xpath, "ip")) {
            ip_addr_str_to_binary(old_val->data.string_val, addr, is_ipv6);
            has_addr = true;
          } else if (sr_xpath_node_name_eq(old_val->xpath, "prefix-length")) {
            prefix = old_val->data.uint8_val;
            has_prefix = true;
          } else if (sr_xpath_node_name_eq(old_val->xpath, "netmask")) {
            prefix = netmask_to_prefix(old_val->data.string_val);
            has_prefix = true;
          }
          if (has_addr && has_prefix) {
            op_rc = interface_ipv46_config_add_remove(
                if_name, addr, prefix, is_ipv6, false /* !add */);
          }
        }
        break;
      default:
        break;
    }
    if (SR_ERR_INVAL_ARG == op_rc) {
      sr_set_error(session, "Invalid interface name.",
                   new_val ? new_val->xpath : old_val->xpath);
    }
    free(if_name);
    sr_free_val(old_val);
    sr_free_val(new_val);
  }
  sr_free_change_iter(iter);

  return op_rc;
}

/**
 * @brief Callback to be called by any config change under
 * "/ietf-interfaces:interfaces-state/interface" path. Does not provide any
 * functionality, needed just to cover not supported config leaves.
 */
static int ietf_interface_change_cb(sr_session_ctx_t *session,
                                    const char *module_name, const char *xpath,
                                    sr_event_t event, uint32_t request_id,
                                    void *private_data) {
  return SR_ERR_OK;
}

int ietf_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription) {
  int rc = SR_ERR_OK;
  SRP_LOG_DBGMSG("Subscriging ietf.");

  //
  rc = sr_module_change_subscribe(
      session, "ietf-interfaces", "/ietf-interfaces:interfaces/interface",
      ietf_interface_change_cb, NULL, 0,
      SR_SUBSCR_CTX_REUSE | SR_SUBSCR_ENABLED, subscription);

  if (rc != SR_ERR_OK) {
    SRP_LOG_DBGMSG(
        "Problem in subscription /ietf-interfaces:interfaces/interface\n");
    goto error;
  }

  rc = sr_module_change_subscribe(
      session, "ietf-interfaces",
      "/ietf-interfaces:interfaces/interface/enabled",
      ietf_interface_enable_disable_cb, NULL, 100,
      SR_SUBSCR_CTX_REUSE | SR_SUBSCR_ENABLED, subscription);
  if (rc != SR_ERR_OK) {
    SRP_LOG_DBGMSG(
        "Problem in subscription "
        "/ietf-interfaces:interfaces/interface/enabled\n");
    goto error;
  }

  // rc = sr_module_change_subscribe(session,
  // "ietf-interfaces","/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address",
  // ietf_interface_ipv46_address_change_cb,
  rc = sr_module_change_subscribe(
      session, "ietf-interfaces", "/ietf-interfaces:interfaces",
      ietf_interface_ipv46_address_change_cb, NULL, 99,
      SR_SUBSCR_CTX_REUSE | SR_SUBSCR_ENABLED, subscription);

  if (rc != SR_ERR_OK) {
    SRP_LOG_DBGMSG(
        "Problem in subscription "
        "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address\n");
    goto error;
  }

  // rc = sr_module_change_subscribe(session,
  // "ietf-interfaces","/ietf-interfaces:interfaces/interface/ietf-ip:ipv6/address",
  // ietf_interface_ipv46_address_change_cb,
  //                                         NULL,
  //                                         98, SR_SUBSCR_CTX_REUSE |
  //                                         SR_SUBSCR_ENABLED, subscription);

  if (rc != SR_ERR_OK) {
    SRP_LOG_DBGMSG(
        "Problem in subscription "
        "/ietf-interfaces:interfaces/interface/ietf-ip:ipv6/address\n");
    goto error;
  }

  /*   rc = sr_dp_get_items_subscribe(session,
     "/ietf-interfaces:interfaces-state", ietf_interface_state_cb, NULL,
     SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription
     /ietf-interfaces:interfaces-state\n"); goto error;
     }*/

  SRP_LOG_INFMSG("ietf initialized successfully.");
  return SR_ERR_OK;

error:
  SRP_LOG_ERRMSG("Error by initialization of the ietf.");
  return rc;
}
