/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file stats.c
 * \brief Implementation of stats.
 */

#include <string.h>

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/stats.h>
#include <hicn/util/log.h>

#include "../object_vft.h"
#include "../object_private.h"

int hc_stats_snprintf(char *s, size_t size, const hc_stats_t *stats) {
#if 0
            INFO("Connection #%d:", conn_stats->id);
            INFO("\tinterests received: %d pkts (%d bytes)",
                 conn_stats->stats.interests.rx_pkts,
                 conn_stats->stats.interests.rx_bytes);
            INFO("\tinterests transmitted: %d pkts (%d bytes)",
                 conn_stats->stats.interests.tx_pkts,
                 conn_stats->stats.interests.tx_bytes);
            INFO("\tdata received: %d pkts (%d bytes)",
                 conn_stats->stats.data.rx_pkts,
                 conn_stats->stats.data.rx_bytes);
            INFO("\tdata transmitted: %d pkts (%d bytes)",
                 conn_stats->stats.data.tx_pkts,
                 conn_stats->stats.data.tx_bytes);
#endif
  return 0;
}

int hc_stats_get(hc_sock_t *s, hc_data_t **pdata) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.listener = *listener;
  return hc_execute(s, ACTION_GET, OBJECT_TYPE_STATS, &object, pdata);
}

int hc_stats_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_STATS, NULL, pdata);
}
