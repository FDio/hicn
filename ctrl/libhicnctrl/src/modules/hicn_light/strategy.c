#include <assert.h>
#include "strategy.h"

#include <hicn/ctrl/hicn-light.h>

static int hicnlight_strategy_parse(const u8 *buffer, size_t size,
                                    hc_strategy_t *strategy) {
  return -1;
}

int _hicnlight_strategy_parse(const uint8_t *buffer, size_t size,
                              hc_object_t *object) {
  return hicnlight_strategy_parse(buffer, size, &object->strategy);
}

int hicnlight_strategy_serialize_create(const hc_object_t *object,
                                        uint8_t *packet) {
  return -1;
}

int hicnlight_strategy_serialize_delete(const hc_object_t *object,
                                        uint8_t *packet) {
  return -1;
}

int hicnlight_strategy_serialize_list(const hc_object_t *object,
                                      uint8_t *packet) {
  assert(!object);
  return -1;
}
#if 0
// per prefix
static hc_result_t *_strategy_set_serialize(hc_sock_t *socket,
                                            hc_strategy_t *strategy) {
  return -1;
  hc_result_t *res = malloc(sizeof(*res));
  char strategy_s[MAXSZ_HC_STRATEGY];
  strncpy(strategy->name, strategy_str(strategy->type),
          MAXSZ_STRATEGY_NAME - 1);

  int rc = hc_strategy_snprintf(strategy_s, MAXSZ_HC_STRATEGY, strategy);
  if (rc >= MAXSZ_HC_STRATEGY)
    WARN("[hicnlight_strategy_create] Unexpected truncation of strategy string");
  DEBUG("[hicnlight_strategy_create] strategy=%s", strategy_s);

  if (!IS_VALID_FAMILY(strategy->family) ||
      !IS_VALID_STRATEGY_TYPE(strategy->type)) {
    res->success = false;
    return res;
  }

  msg_strategy_set_t msg = {.header =
                                {
                                    .message_type = REQUEST_LIGHT,
                                    .command_id = COMMAND_TYPE_STRATEGY_SET,
                                    .length = 1,
                                    .seq_num = 0,
                                },
                            .payload = {
                                .address = strategy->address,
                                .family = strategy->family,
                                .len = strategy->len,
                                .type = strategy->type,
                            }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_STRATEGY_SET,
      .size_in = sizeof(cmd_strategy_set_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .header = msg.header,
              .payload.strategy_set = msg.payload,
          },
      .params = params,
      .async = false,
      .success = true,
  };
  return res;
}
#endif

#if 0
static hc_result_t *_strategy_add_local_prefix_serialize(
    hc_sock_t *socket, hc_strategy_t *strategy) {
  hc_result_t *res = malloc(sizeof(*res));
  char strategy_s[MAXSZ_HC_STRATEGY];
  strncpy(strategy->name, strategy_str(strategy->type),
          MAXSZ_STRATEGY_NAME - 1);

  int rc = hc_strategy_snprintf(strategy_s, MAXSZ_HC_STRATEGY, strategy);
  if (rc >= MAXSZ_HC_STRATEGY)
    WARN("[hicnlight_strategy_create] Unexpected truncation of strategy string");
  DEBUG("[hicnlight_strategy_create] strategy=%s", strategy_s);

  if (!IS_VALID_FAMILY(strategy->family) ||
      !IS_VALID_STRATEGY_TYPE(strategy->type) ||
      !IS_VALID_FAMILY(strategy->local_family)) {
    res->success = false;
    return res;
  }

  msg_strategy_add_local_prefix_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_STRATEGY_ADD_LOCAL_PREFIX,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .type = strategy->type,
          .address = strategy->address,
          .family = strategy->family,
          .len = strategy->len,
          .local_address = strategy->local_address,
          .local_family = strategy->local_family,
          .local_len = strategy->local_len,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_STRATEGY_ADD_LOCAL_PREFIX,
      .size_in = sizeof(cmd_strategy_add_local_prefix_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .header = msg.header,
              .payload.strategy_add_local_prefix = msg.payload,
          },
      .params = params,
      .async = false,
      .success = true,
  };
  return res;
}
#endif

#if 0
static int hicnlight_strategy_set(hc_sock_t *socket, hc_strategy_t *strategy) {
  hc_result_t *result = _strategy_set_serialize(socket, strategy);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = hicnlight_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
  return -1;  // XXX added
}

static int hicnlight_strategy_add_local_prefix(hc_sock_t *socket,
                                               hc_strategy_t *strategy) {
  hc_result_t *result = _strategy_add_local_prefix_serialize(socket, strategy);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = hicnlight_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
  return -1;  // XXX added
}

/* How to retrieve that from the forwarder ? */
static const char *strategies[] = {
    "random",
    "load_balancer",
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

static int hicnlight_strategy_list(hc_sock_t *s, hc_data_t **data) {
  int rc;

  *data = hc_data_create(0, sizeof(hc_strategy_t), NULL);

  for (unsigned i = 0; i < ARRAY_SIZE(strategies); i++) {
    hc_strategy_t *strategy = (hc_strategy_t *)hc_data_get_next(*data);
    if (!strategy) return -1;
    rc = snprintf(strategy->name, MAXSZ_STRATEGY_NAME, "%s", strategies[i]);
    if (rc >= MAXSZ_STRATEGY_NAME)
      WARN("[hc_strategy_list] Unexpected truncation of strategy name string");
    (*data)->size++;
  }
  return -1;
}
#endif

DECLARE_MODULE_OBJECT_OPS(hicnlight, strategy);
