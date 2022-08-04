#include <assert.h>
#include <hicn/ctrl/api.h>
#include <hicn/util/log.h>

#include "base.h"
#include "../../object_private.h"
#include "subscription.h"

static int hicnlight_subscription_parse(const u8 *buffer, size_t size,
                                        hc_subscription_t *subscription) {
  /* We should never have to parse subscriptions */
  return -1;
}

int _hicnlight_subscription_parse(const uint8_t *buffer, size_t size,
                                  hc_object_t *object) {
  return hicnlight_subscription_parse(buffer, size, &object->subscription);
}

/* SUBSCRIPTION CREATE */

int hicnlight_subscription_serialize_create(const hc_object_t *object,
                                            uint8_t *packet) {
  const hc_subscription_t *subscription = &object->subscription;

  msg_subscription_add_t *msg = (msg_subscription_add_t *)packet;
  *msg = (msg_subscription_add_t){
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_SUBSCRIPTION_ADD,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {.topics = subscription->topics}};

  return sizeof(msg_subscription_add_t);
}

/* SUBSCRIPTION DELETE */

int hicnlight_subscription_serialize_delete(const hc_object_t *object,
                                            uint8_t *packet) {
  const hc_subscription_t *subscription = &object->subscription;

  msg_subscription_remove_t *msg = (msg_subscription_remove_t *)packet;
  *msg = (msg_subscription_remove_t){
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_SUBSCRIPTION_REMOVE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {.topics = subscription->topics}};

  return sizeof(msg_subscription_remove_t);
}

int hicnlight_subscription_serialize_list(const hc_object_t *object,
                                          uint8_t *packet) {
  assert(!object);
  return -1;
}

DECLARE_MODULE_OBJECT_OPS(hicnlight, subscription);
