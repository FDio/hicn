#ifdef WITH_POLICY_STATS

// This has to be included first because of _GNU_SOURCE
#include <hicn/core/forwarder.h>

#include <hicn/core/connection_table.h>
#include <hicn/base/loop.h>
#include <hicn/util/log.h>
#include <hicn/core/ticks.h>
#include <hicn/policy.h>
#include <hicn/core/fib.h>

#include "policy_stats.h"

#define ALPHA 0.9
#define STATS_INTERVAL 1000 /* ms */

static int policy_stats_mgr_tick(void* mgr_arg, int fd, void* data) {
  policy_stats_mgr_t* mgr = mgr_arg;
  assert(mgr);
  assert(!data);

  uint64_t now = ticks_now();

  /* Loop over FIB entries to compute statistics from counters */
  const fib_t* fib = forwarder_get_fib(mgr->forwarder);
  fib_entry_t* entry;

  fib_foreach_entry(fib, entry, {
    policy_stats_update(&entry->policy_stats, &entry->policy_counters, now);
  });

  return 0;
}

int policy_stats_mgr_initialize(policy_stats_mgr_t* mgr, void* forwarder) {
  mgr->forwarder = forwarder;

  loop_timer_create(&mgr->timer, MAIN_LOOP, mgr, policy_stats_mgr_tick, NULL);
  if (!mgr->timer) {
    ERROR("Error allocating prefix stats mgr timer.");
    return -1;
  }

  if (loop_timer_register(mgr->timer, STATS_INTERVAL) < 0) {
    ERROR("Error registering prefix stats mgr timer.");
    return -1;
  }

  return 0;
}

void policy_stats_mgr_finalize(policy_stats_mgr_t* mgr) {
  loop_event_unregister(mgr->timer);
  loop_event_free(mgr->timer);
}

void policy_stats_on_retransmission(const policy_stats_mgr_t* mgr,
                                    policy_counters_t* counters,
                                    const nexthops_t* nexthops) {
  connection_table_t* table = forwarder_get_connection_table(mgr->forwarder);
  unsigned nexthop;
  nexthops_foreach(nexthops, nexthop, {
#ifdef WITH_POLICY
    const connection_t* conn = connection_table_at(table, nexthop);

    if (connection_has_tag(conn, POLICY_TAG_WIRED))
      counters->wired.num_losses++;
    if (connection_has_tag(conn, POLICY_TAG_WIFI)) counters->wifi.num_losses++;
    if (connection_has_tag(conn, POLICY_TAG_CELLULAR))
      counters->cellular.num_losses++;
#endif /* WITH_POLICY */
    counters->all.num_losses++;
  });
}

#define UPDATE_TAG_STATS(TAG, NAME)                                \
  do {                                                             \
    if (connection_has_tag(conn, TAG)) {                           \
      counters->NAME.num_packets++;                                \
      counters->NAME.num_bytes += msg_size;                        \
      stats->NAME.latency =                                        \
          ALPHA * stats->NAME.latency + (1 - ALPHA) * (double)rtt; \
      counters->NAME.latency_idle = 0;                             \
    }                                                              \
  } while (0)

/* Update statistic counters upon Data packet reception */
void policy_stats_on_data(const policy_stats_mgr_t* mgr, policy_stats_t* stats,
                          policy_counters_t* counters,
                          const nexthops_t* nexthops, const msgbuf_t* msgbuf,
                          Ticks rtt) {
#ifdef WITH_POLICY
  forwarder_t* forwarder = mgr->forwarder;
  connection_table_t* table = forwarder_get_connection_table(forwarder);
#endif /* WITH_POLICY */

  size_t msg_size = msgbuf_get_len(msgbuf);

  unsigned nexthop;
  nexthops_foreach(nexthops, nexthop, {
#ifdef WITH_POLICY
    const connection_t* conn = connection_table_at(table, nexthop);
    if (!conn) continue;

    UPDATE_TAG_STATS(POLICY_TAG_WIRED, wired);
    UPDATE_TAG_STATS(POLICY_TAG_WIFI, wifi);
    UPDATE_TAG_STATS(POLICY_TAG_CELLULAR, cellular);
#endif /* WITH_POLICY */
  });

  stats->all.latency = ALPHA * stats->all.latency + (1 - ALPHA) * (double)rtt;
  counters->all.latency_idle = 0;
  counters->all.num_packets++;
  counters->all.num_bytes += msg_size;
}

void policy_stats_on_timeout(const policy_stats_mgr_t* mgr,
                             policy_counters_t* counters,
                             const nexthops_t* nexthops) {
#ifdef WITH_POLICY
  connection_table_t* table = forwarder_get_connection_table(mgr->forwarder);

  unsigned nexthop;
  nexthops_foreach(nexthops, nexthop, {
    const connection_t* conn = connection_table_at(table, nexthop);
    if (!conn) continue;
    if (connection_has_tag(conn, POLICY_TAG_WIRED))
      counters->wired.num_losses++;
    if (connection_has_tag(conn, POLICY_TAG_WIFI)) counters->wifi.num_losses++;
    if (connection_has_tag(conn, POLICY_TAG_CELLULAR))
      counters->cellular.num_losses++;
  });
#endif /* WITH_POLICY */

  counters->all.num_losses++;
}

#define UPDATE_TYPE(TYPE)                                                      \
  do {                                                                         \
    /* (a) throughput */                                                       \
    if (counters->TYPE.num_bytes > 0) {                                        \
      throughput = counters->TYPE.num_bytes / (now - counters->last_update);   \
      throughput = throughput * 8 / 1024;                                      \
      if (throughput < 0) throughput = 0;                                      \
    } else {                                                                   \
      throughput = 0;                                                          \
    }                                                                          \
    stats->TYPE.throughput =                                                   \
        ALPHA * stats->TYPE.throughput + (1 - ALPHA) * throughput;             \
                                                                               \
    /* (b) loss rate */                                                        \
    if ((counters->TYPE.num_losses > 0) && (counters->TYPE.num_packets > 0)) { \
      loss_rate = counters->TYPE.num_losses / counters->TYPE.num_packets;      \
      loss_rate *= 100;                                                        \
    } else {                                                                   \
      loss_rate = 0;                                                           \
    }                                                                          \
    stats->TYPE.loss_rate =                                                    \
        ALPHA * stats->TYPE.loss_rate + (1 - ALPHA) * loss_rate;               \
                                                                               \
    /* (c) latency */                                                          \
    counters->TYPE.latency_idle++;                                             \
    if (counters->TYPE.latency_idle > 1) stats->TYPE.latency = 0;              \
                                                                               \
    /* (d) Reset counters */                                                   \
    counters->TYPE.num_bytes = 0;                                              \
    counters->TYPE.num_losses = 0;                                             \
    counters->TYPE.num_packets = 0;                                            \
  } while (0)

void policy_stats_update(policy_stats_t* stats, policy_counters_t* counters,
                         uint64_t now) {
  double throughput;
  double loss_rate;

  if (now == counters->last_update) return;

#ifdef WITH_POLICY
  UPDATE_TYPE(wired);
  UPDATE_TYPE(wifi);
  UPDATE_TYPE(cellular);
#endif /* WITH_POLICY */
  UPDATE_TYPE(all);

  counters->last_update = now;
}

#endif /* WITH_POLICY_STATS */
