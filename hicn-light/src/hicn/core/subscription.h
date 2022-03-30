/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#ifndef HICNLIGHT_SUBSCRIPTION_H
#define HICNLIGHT_SUBSCRIPTION_H

#include <hicn/ctrl/api.h>
#include <stddef.h>

/*----------------------------------------------------------------------------*
 * Topics
 *----------------------------------------------------------------------------*/

bool topics_contains(hc_topics_t topic_list, hc_topic_t topic);

/*----------------------------------------------------------------------------*
 * Subscriptions
 *----------------------------------------------------------------------------*/

typedef struct subscription_table_s subscription_table_t;

subscription_table_t *subscription_table_create();

void subscription_table_free(subscription_table_t *subscriptions);

/**
 * @brief Add topic subscriptions for a connection.
 *
 * @param subscriptions The pointer to the subscription table
 * @param topics Topics the connection wants to subscribe to
 * @param connection_id Identifier of the connection
 * @return int 0 for success, -1 for error, -2 if already esisting subscription
 * for at least one of the topic for
 */
int subscription_table_add_topics_for_connection(
    subscription_table_t *subscriptions, hc_topics_t topics,
    unsigned connection_id);

/**
 * @brief Remove topic subscriptions for a connection.
 *
 * @param subscriptions The pointer to the subscription table
 * @param topics Topics the connection wants to unsubscribe to
 * @param connection_id Identifier of the connection
 * @return int Number of removed subscriptions
 */
int subscription_table_remove_topics_for_connection(
    subscription_table_t *subscriptions, hc_topics_t topics,
    unsigned connection_id);

/**
 * @brief Get the topics a connection has subscribed to.
 *
 * @param subscriptions The pointer to the subscription table
 * @param connection_id Identifier of the connection
 * @return hc_topics_t
 */
hc_topics_t subscription_table_get_topics_for_connection(
    subscription_table_t *subscriptions, unsigned connection_id);

/**
 * @brief Get the connections that have a subscription for the specified topic.
 *
 * @param subscriptions The pointer to the subscription table
 * @param topic Topic to retrieve the subscriptions for
 * @return unsigned* Array containing the connection ids associated with the
 * specified topic
 */
unsigned *subscription_table_get_connections_for_topic(
    subscription_table_t *subscriptions, hc_topic_t topic);

/**
 * @brief Print the subscription table containing, for each topic, the list
 * of connections with a subsctiption.
 *
 * @param subscriptions The pointer to the subscription table
 */
void subscription_table_print(subscription_table_t *subscriptions);

#endif  // HICNLIGHT_SUBSCRIPTION_H