#include "cache.h"

/* CACHE SET STORE */

static int _hcng_cache_set_store_internal(hc_sock_t *socket, hc_cache_t *cache,
                                          bool async) {
#if 0
  msg_cache_set_store_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CACHE_SET_STORE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .activate = cache->store,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_STORE,
      .cmd_id = COMMAND_TYPE_CACHE_SET_STORE,
      .size_in = sizeof(cmd_cache_set_store_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
#endif
  return 0;  // XXX added
}

static int _hcng_cache_set_store(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_store_internal(s, cache, false);
}

static int _hcng_cache_set_store_async(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_store_internal(s, cache, true);
}

/* CACHE SET SERVE */

static int _hcng_cache_set_serve_internal(hc_sock_t *socket, hc_cache_t *cache,
                                          bool async) {
#if 0
  msg_cache_set_serve_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CACHE_SET_SERVE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .activate = cache->serve,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SERVE,
      .cmd_id = COMMAND_TYPE_CACHE_SET_SERVE,
      .size_in = sizeof(cmd_cache_set_serve_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
#endif
  return 0;  /// added
}

static int _hcng_cache_set_serve(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_serve_internal(s, cache, false);
}

static int _hcng_cache_set_serve_async(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_serve_internal(s, cache, true);
}

/* CACHE CLEAR */

static int _hcng_cache_clear_internal(hc_sock_t *socket, hc_cache_t *cache,
                                      bool async) {
#if 0
  msg_cache_clear_t msg = {.header = {
                               .message_type = REQUEST_LIGHT,
                               .command_id = COMMAND_TYPE_CACHE_CLEAR,
                               .length = 1,
                               .seq_num = 0,
                           }};

  hc_command_params_t params = {
      .cmd = ACTION_CLEAR,
      .cmd_id = COMMAND_TYPE_CACHE_CLEAR,
      .size_in = sizeof(cmd_cache_clear_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
#endif
  return 0;  // XXX added
}

static int _hcng_cache_clear(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_clear_internal(s, cache, false);
}

/* CACHE PARSE */

static int hc_cache_parse(void *in, hc_cache_info_t *cache_info) {
  cmd_cache_list_reply_t *item = (cmd_cache_list_reply_t *)in;
  *cache_info = (hc_cache_info_t){.store = item->store_in_cs,
                                  .serve = item->serve_from_cs,
                                  .cs_size = item->cs_size,
                                  .num_stale_entries = item->num_stale_entries};

  return 0;
}

/* CACHE LIST */

static hc_result_t *_hcng_cache_list_serialize(hc_sock_t *socket,
                                               hc_data_t **pdata, bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  DEBUG("[hc_cache_list] async=%s", BOOLSTR(async));

  msg_cache_list_t msg = {.header = {
                              .message_type = REQUEST_LIGHT,
                              .command_id = COMMAND_TYPE_CACHE_LIST,
                              .length = 0,
                              .seq_num = 0,
                          }};

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_CACHE_LIST,
      .size_in = sizeof(cmd_cache_list_reply_t),
      .size_out = sizeof(hc_cache_info_t),
      .parse = (HC_PARSE)hc_cache_parse,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .header = msg.header,
              .payload.cache_list = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static int _hcng_cache_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                     bool async) {
#if 0
  hc_result_t *result = _hcng_cache_list_serialize(socket, pdata, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, pdata,
                                result->async);
  }

  hc_result_free(result);
  return ret;
#endif
  return 0;  // XXX added
}

static int _hcng_cache_list(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_cache_list_internal(s, pdata, false);
}
