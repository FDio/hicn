#ifndef HICNCTRL_MODULES_HICNLIGHT_BASE_H
#define HICNCTRL_MODULES_HICNLIGHT_BASE_H

#include <hicn/ctrl/hicn-light.h>

#if 1
#ifdef __APPLE__
#define RANDBYTE() (u8)(arc4random() & 0xFF)
#else
#define RANDBYTE() (u8)(random() & 0xFF)
#endif
#else
#define RANDBYTE() (u8)(rand() & 0xFF)
#endif

#define foreach_hc_command     \
  _(connection_add)            \
  _(connection_remove)         \
  _(connection_list)           \
  _(listener_add)              \
  _(listener_remove)           \
  _(listener_list)             \
  _(route_add)                 \
  _(route_remove)              \
  _(route_list)                \
  _(cache_set_store)           \
  _(cache_set_serve)           \
  _(cache_clear)               \
  _(cache_list)                \
  _(strategy_set)              \
  _(strategy_add_local_prefix) \
  _(wldr_set)                  \
  _(punting_add)               \
  _(mapme_activator)           \
  _(mapme_timing)              \
  _(subscription_add)          \
  _(subscription_remove)

#if 0
const char *command_type_str[] = {
#define _(l, u) [COMMAND_TYPE_##u] = STRINGIZE(u),
    foreach_command_type
#undef _
};
#endif

typedef union {
#define _(x) cmd_##x##_t x;
  foreach_hc_command
#undef _
} hc_msg_payload_t;

typedef cmd_header_t hc_msg_header_t;

typedef struct hc_msg_s {
  hc_msg_header_t header;
  hc_msg_payload_t payload;
} hc_msg_t;

#endif /* HICNCTRL_MODULES_HICNLIGHT_BASE_H */
