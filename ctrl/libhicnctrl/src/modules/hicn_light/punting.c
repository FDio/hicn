#include "punting.h"

static int _hcng_punting_create_internal(hc_sock_t *socket,
                                         hc_punting_t *punting, bool async) {
#if 0
  int rc;

  if (hc_punting_validate(punting) < 0) return -1;

  struct {
    cmd_header_t hdr;
    cmd_punting_add_t payload;
  } msg = {.hdr =
               {
                   .message_type = REQUEST_LIGHT,
                   .command_id = COMMAND_TYPE_PUNTING_ADD,
                   .length = 1,
                   .seq_num = 0,
               },
           .payload = {
               .address = punting->prefix,
               .family = punting->family,
               .len = punting->prefix_len,
           }};
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                punting->face_id);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN("[_hc_punting_create] Unexpected truncation of symbolic name string");

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_PUNTING_ADD,
      .size_in = sizeof(cmd_punting_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
#endif
  return 0;  // XXX added
}

static int _hcng_punting_create(hc_sock_t *s, hc_punting_t *punting) {
  return _hcng_punting_create_internal(s, punting, false);
}

static int _hcng_punting_create_async(hc_sock_t *s, hc_punting_t *punting) {
  return _hcng_punting_create_internal(s, punting, true);
}

static int _hcng_punting_get(hc_sock_t *s, hc_punting_t *punting,
                             hc_punting_t **punting_found) {
  ERROR("hc_punting_get not (yet) implemented.");
  return -1;
}

static int _hcng_punting_delete(hc_sock_t *s, hc_punting_t *punting) {
  ERROR("hc_punting_delete not (yet) implemented.");
  return -1;
}

#if 0
static int hc_punting_parse(void * in, hc_punting_t * punting)
{
    ERROR("hc_punting_parse not (yet) implemented.");
    return -1;
}
#endif

static int _hcng_punting_list(hc_sock_t *s, hc_data_t **pdata) {
  ERROR("hc_punting_list not (yet) implemented.");
  return -1;
}
