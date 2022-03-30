/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include "subscription.h"
#include <hicn/base/vector.h>
#include <hicn/util/log.h>

/*----------------------------------------------------------------------------*
 * Topics and events
 *----------------------------------------------------------------------------*/

bool topics_contains(hc_topics_t topic_list, hc_topic_t topic) {
  return ((topic_list) & (topic));
}

#define topic_is_set(topic_list, topic_index) \
  ((topic_list) & (1 << (topic_index)))

const char *event_str[] = {
#define _(x) [EVENT_##x] = #x,
    foreach_event_type
#undef _
};

/*----------------------------------------------------------------------------*
 * Subscriptions
 *----------------------------------------------------------------------------*/

struct subscription_table_s {
  unsigned *table[TOPIC_N];
};

subscription_table_t *subscription_table_create() {
  subscription_table_t *subscriptions = malloc(sizeof(subscription_table_t));
  for (int i = 0; i < NUM_TOPICS; i++)
    vector_init(subscriptions->table[i], 0, 0);

  return subscriptions;
}

void subscription_table_free(subscription_table_t *subscriptions) {
  for (int i = 0; i < NUM_TOPICS; i++) vector_free(subscriptions->table[i]);
  free(subscriptions);
}

int subscription_table_add_topics_for_connection(
    subscription_table_t *subscriptions, hc_topics_t topics,
    unsigned connection_id) {
  bool is_subscription_already_present = false;
  for (int topic_index = 0; topic_index < NUM_TOPICS; topic_index++) {
    if (topic_is_set(topics, topic_index)) {
      int num_duplicates = vector_remove_unordered(
          subscriptions->table[topic_index], connection_id);

      int ret = vector_push(subscriptions->table[topic_index], connection_id);
      if (ret < 0) {
        ERROR("Unable to perform subscription for connection %d, topic %s",
              connection_id, object_str(topic_index));
        return -1;
      }

      if (num_duplicates > 0) {
        DEBUG("Connection %d had already a subscription for topic %s",
              connection_id, object_str(topic_index));
        is_subscription_already_present = true;
      }
    }
  }
  return is_subscription_already_present ? -2 : 0;
}

int subscription_table_remove_topics_for_connection(
    subscription_table_t *subscriptions, hc_topics_t topics,
    unsigned connection_id) {
  int num_subscriptions_removed = 0;
  for (int topic_index = 0; topic_index < NUM_TOPICS; topic_index++) {
    if (topic_is_set(topics, topic_index)) {
      int num_duplicates = vector_remove_unordered(
          subscriptions->table[topic_index], connection_id);
      if (num_duplicates <= 0) {
        continue;
      }
      num_subscriptions_removed++;
    }
  }
  return num_subscriptions_removed;
}

hc_topics_t subscription_table_get_topics_for_connection(
    subscription_table_t *subscriptions, unsigned connection_id) {
  hc_topics_t topics = 0;
  for (int topic_index = 0; topic_index < NUM_TOPICS; topic_index++) {
    unsigned *conn_id;
    bool found = false;
    vector_foreach(subscriptions->table[topic_index], conn_id, {
      if (*conn_id == connection_id) {
        found = true;
        break;
      }
    });
    if (found) topics |= (1 << topic_index);
  }
  return topics;
}

unsigned *subscription_table_get_connections_for_topic(
    subscription_table_t *subscriptions, hc_topic_t topic) {
  int topic_index = object_from_topic(topic);
  return subscriptions->table[topic_index];
}

void subscription_table_print(subscription_table_t *subscriptions) {
  for (int topic_index = OBJECT_UNDEFINED + 1; topic_index < NUM_TOPICS;
       topic_index++) {
    printf("topic %s (%lu subscription/s) from connection/s: [ ",
           object_str(topic_index),
           (unsigned long)vector_len(subscriptions->table[topic_index]));
    unsigned *connection_id;
    vector_foreach(subscriptions->table[topic_index], connection_id,
                   { printf("%d ", *connection_id); });
    printf("]\n");
  }
}