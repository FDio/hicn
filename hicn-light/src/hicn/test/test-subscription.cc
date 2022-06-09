/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <gtest/gtest.h>

extern "C" {
#include <hicn/core/subscription.h>
#include <hicn/util/vector.h>
}

static inline unsigned CONN_ID = 1;
static inline unsigned CONN_ID_2 = 2;

class SubscriptionTest : public ::testing::Test {
 protected:
  SubscriptionTest() { subscriptions = subscription_table_create(); }
  virtual ~SubscriptionTest() { subscription_table_free(subscriptions); }

  subscription_table_t *subscriptions;
};

TEST_F(SubscriptionTest, CreateSubscriptionTable) {
  // Check subscription table allocation
  ASSERT_NE(subscriptions, nullptr);
}

TEST_F(SubscriptionTest, SetTopic) {
  hc_topics_t topics = TOPIC_STRATEGY;

  // Check that only the topic desired has been subscribed to
  for (int topic = TOPIC_UNDEFINED; topic < TOPIC_N; topic <<= 1) {
    if (topic == TOPIC_STRATEGY) {
      EXPECT_TRUE(topics_contains(topics, (hc_topic_t)topic));
      continue;
    }
    EXPECT_FALSE(topics_contains(topics, (hc_topic_t)topic));
  }
}

TEST_F(SubscriptionTest, GetObjectFromTopic) {
  hc_object_type_t object_type = object_from_topic(TOPIC_STRATEGY);
  EXPECT_EQ(object_type, OBJECT_STRATEGY);

  object_type = object_from_topic(TOPIC_FACE);
  EXPECT_EQ(object_type, OBJECT_FACE);
}

TEST_F(SubscriptionTest, AddSubscription) {
  hc_topics_t topics = TOPIC_STRATEGY;
  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, topics);
}

TEST_F(SubscriptionTest, AddAndRemoveSubscriptionForAllTopics) {
  hc_topics_t topics = ALL_TOPICS;
  int ret = subscription_table_add_topics_for_connection(subscriptions,
                                                         ALL_TOPICS, CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  int num_subscriptions_removed =
      subscription_table_remove_topics_for_connection(subscriptions, topics,
                                                      CONN_ID);
  EXPECT_EQ(num_subscriptions_removed, NUM_TOPICS);

  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, 0u);
}

// Failure while adding subscription cannot be tested since it depends on vector
// reallocation

TEST_F(SubscriptionTest, AddSubscriptionAlreadyAdded) {
  hc_topics_t topics = TOPIC_STRATEGY;
  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  // Subscribe again to same topic
  ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                     CONN_ID);
  EXPECT_EQ(ret, -2);  // -2 = already-added subscription

  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, topics);
}

TEST_F(SubscriptionTest, GetSubscriptionsForConnectionWithoutSubscriptions) {
  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, (hc_topics_t)0);
}

TEST_F(SubscriptionTest, GetSubscriptionsForConnectionWithMultipleSubs) {
  hc_topics_t topics = TOPIC_STRATEGY | TOPIC_FACE;
  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, topics);

  // Add another subscription
  ret = subscription_table_add_topics_for_connection(subscriptions, TOPIC_PROBE,
                                                     CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, topics |= TOPIC_PROBE);
}

TEST_F(SubscriptionTest, RemoveSubscription) {
  // Add subscriptions
  hc_topics_t topics = TOPIC_STRATEGY | TOPIC_FACE;
  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  // Remove one of the previously added subscriptions
  int num_subscriptions_removed =
      subscription_table_remove_topics_for_connection(subscriptions,
                                                      TOPIC_STRATEGY, CONN_ID);
  EXPECT_EQ(num_subscriptions_removed, 1);

  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, TOPIC_FACE);
}

TEST_F(SubscriptionTest, RemoveMultipleSubscriptions) {
  // Add subscriptions
  hc_topics_t topics = TOPIC_STRATEGY | TOPIC_FACE | TOPIC_PROBE;
  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  // Remove two of the previously added subscriptions
  int num_subscriptions_removed =
      subscription_table_remove_topics_for_connection(
          subscriptions, TOPIC_STRATEGY | TOPIC_FACE, CONN_ID);
  EXPECT_EQ(num_subscriptions_removed, 2);

  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, TOPIC_PROBE);
}

TEST_F(SubscriptionTest, RemoveNonRegistredSubscription) {
  // Remove a subscription that is not present
  int num_subscriptions_removed =
      subscription_table_remove_topics_for_connection(subscriptions,
                                                      TOPIC_PROBE, CONN_ID);
  EXPECT_EQ(num_subscriptions_removed, 0);

  // Add two new subscriptions
  hc_topics_t topics = TOPIC_STRATEGY | TOPIC_FACE;
  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  // Remove subscription that was not registred previously
  num_subscriptions_removed = subscription_table_remove_topics_for_connection(
      subscriptions, TOPIC_PROBE, CONN_ID);
  EXPECT_EQ(num_subscriptions_removed, 0);

  hc_topics_t topics_ret =
      subscription_table_get_topics_for_connection(subscriptions, CONN_ID);
  EXPECT_EQ(topics_ret, topics);
}

TEST_F(SubscriptionTest, GetConnectionsForSubscription) {
  // Add subscriptions for two connections
  hc_topics_t topics = TOPIC_STRATEGY | TOPIC_FACE;
  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         CONN_ID);
  EXPECT_EQ(ret, 0);  // 0 = success

  topics = TOPIC_STRATEGY;
  ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                     CONN_ID_2);
  EXPECT_EQ(ret, 0);  // 0 = success

  // Check the connections associated with the strategy topic
  unsigned *conn_ids = subscription_table_get_connections_for_topic(
      subscriptions, TOPIC_STRATEGY);
  EXPECT_EQ(vector_len(conn_ids), 2u);
  EXPECT_TRUE(conn_ids[0] == CONN_ID || conn_ids[0] == CONN_ID_2);
  EXPECT_TRUE(conn_ids[1] == CONN_ID || conn_ids[1] == CONN_ID_2);

  // Check the connections associated with the face topic
  conn_ids =
      subscription_table_get_connections_for_topic(subscriptions, TOPIC_FACE);
  EXPECT_EQ(vector_len(conn_ids), 1u);
  EXPECT_EQ(conn_ids[0], (unsigned)CONN_ID);
}