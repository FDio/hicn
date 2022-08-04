#include "policy.h"

/* POLICY CREATE */

static int _hcng_policy_create_internal(hc_sock_t *socket, hc_policy_t *policy,
                                        bool async) {
#if 0
  if (!IS_VALID_FAMILY(policy->family)) return -1;

  struct {
    cmd_header_t hdr;
    cmd_policy_add_t payload;
  } msg = {.hdr =
               {
                   .message_type = REQUEST_LIGHT,
                   COMMAND_TYPE_POLICY_ADD,
                   .length = 1,
                   .seq_num = 0,
               },
           .payload = {
               .address = policy->remote_addr,
               .family = policy->family,
               .len = policy->len,
               .policy = policy->policy,
           }};

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_POLICY_ADD,
      .size_in = sizeof(cmd_policy_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
#endif
  return 0;  // XXX added
}

static int _hcng_policy_create(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_create_internal(s, policy, false);
}

static int _hcng_policy_create_async(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_create_internal(s, policy, true);
}

/* POLICY DELETE */

static int _hcng_policy_delete_internal(hc_sock_t *socket, hc_policy_t *policy,
                                        bool async) {
#if 0
  if (!IS_VALID_FAMILY(policy->family)) return -1;

  struct {
    cmd_header_t hdr;
    cmd_policy_remove_t payload;
  } msg = {.hdr =
               {
                   .message_type = REQUEST_LIGHT,
                   .command_id = COMMAND_TYPE_POLICY_REMOVE,
                   .length = 1,
                   .seq_num = 0,
               },
           .payload = {
               .address = policy->remote_addr,
               .family = policy->family,
               .len = policy->len,
           }};

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = COMMAND_TYPE_POLICY_REMOVE,
      .size_in = sizeof(cmd_policy_remove_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
#endif
  return 0;  // XXX added
}

static int _hcng_policy_delete(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_delete_internal(s, policy, false);
}

static int _hcng_policy_delete_async(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_delete_internal(s, policy, true);
}

/* POLICY PARSE */

static int hc_policy_parse(void *in, hc_policy_t *policy) {
  hc_policy_t *item = (hc_policy_t *)in;

  if (!IS_VALID_ADDRESS(item->address)) {
    ERROR("[hc_policy_parse] Invalid address");
    return -1;
  }
  if (!IS_VALID_FAMILY(item->family)) {
    ERROR("[hc_policy_parse] Invalid family");
    return -1;
  }
  if (!IS_VALID_PREFIX_LEN(item->len)) {
    ERROR("[hc_policy_parse] Invalid len");
    return -1;
  }
  if (!IS_VALID_POLICY(item->policy)) {
    ERROR("[hc_policy_parse] Invalid policy");
    return -1;
  }

  *policy = (hc_policy_t){
      .family = item->family,
      .remote_addr = item->remote_addr,
      .len = item->len,
      .policy = item->policy,
  };
  return 0;
}

/* POLICY LIST */

static int _hcng_policy_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                      bool async) {
#if 0
  struct {
    cmd_header_t hdr;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_POLICY_LIST,
              .length = 0,
              .seq_num = 0,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_POLICY_LIST,
      .size_in = sizeof(hc_policy_t),
      .size_out = sizeof(hc_policy_t),
      .parse = (HC_PARSE)hc_policy_parse,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               pdata, async);
#endif
  return 0;  // XXX added
}

static int _hcng_policy_list(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_policy_list_internal(s, pdata, false);
}

static int _hcng_policy_list_async(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_policy_list_internal(s, pdata, true);
}
