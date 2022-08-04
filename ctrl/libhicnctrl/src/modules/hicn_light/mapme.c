#include "mapme.h"

static int _hcng_mapme_set(hc_sock_t *socket, int enabled) {
#if 0
  msg_mapme_enable_t msg = {.header =
                                {
                                    .message_type = REQUEST_LIGHT,
                                    .command_id = COMMAND_TYPE_MAPME_ENABLE,
                                    .length = 1,
                                    .seq_num = 0,
                                },
                            .payload = {
                                .activate = enabled,
                            }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_ENABLE,
      .size_in = sizeof(cmd_mapme_enable_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_set_discovery(hc_sock_t *socket, int enabled) {
#if 0
  msg_mapme_enable_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SET_DISCOVERY,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .activate = enabled,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_DISCOVERY,
      .size_in = sizeof(cmd_mapme_set_discovery_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_set_timescale(hc_sock_t *socket, uint32_t timescale) {
#if 0
  msg_mapme_set_timescale_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SET_TIMESCALE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .timePeriod = timescale,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_TIMESCALE,
      .size_in = sizeof(cmd_mapme_set_timescale_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_set_retx(hc_sock_t *socket, uint32_t timescale) {
#if 0
  msg_mapme_set_retx_t msg = {.header =
                                  {
                                      .message_type = REQUEST_LIGHT,
                                      .command_id = COMMAND_TYPE_MAPME_SET_RETX,
                                      .length = 1,
                                      .seq_num = 0,
                                  },
                              .payload = {
                                  .timePeriod = timescale,
                              }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_RETX,
      .size_in = sizeof(msg_mapme_set_retx_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_send_update(hc_sock_t *socket, hc_mapme_t *mapme) {
#if 0
  if (!IS_VALID_FAMILY(mapme->family)) return -1;

  msg_mapme_send_update_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SEND_UPDATE,
              .length = 1,
              .seq_num = 0,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_UPDATE,
      .cmd_id = COMMAND_TYPE_MAPME_SEND_UPDATE,
      .size_in = sizeof(msg_mapme_send_update_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}
