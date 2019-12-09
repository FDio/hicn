#ifdef WITH_PREFIX_STATS

#include <parc/algol/parc_EventTimer.h>

#include <hicn/base/connection_table.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/ticks.h>
#include <hicn/policy.h>

#include "prefix_stats.h"

#define ALPHA 0.9
#define STATS_INTERVAL 1000 /* ms */


static
void
prefix_stats_mgr_tick(int fd, PARCEventType type, void *user_data)
{
  Forwarder * forwarder = (Forwarder*)user_data;
  uint64_t now = (uint64_t)forwarder_GetTicks(forwarder);

  /* Loop over FIB entries to compute statistics from counters */
  fib_entry_list_t *fibList = forwarder_GetFibEntries(forwarder);

  for (size_t i = 0; i < fib_entry_list_Length(fibList); i++) {
    fib_entry_t *entry = (fib_entry_t *)fib_entry_list_Get(fibList, i);
    prefix_stats_update(&entry->prefix_stats, &entry->prefix_counters, now);
  }

  fib_entry_list_Destroy(&fibList);
}

void
prefix_stats_mgr_initialize(prefix_stats_mgr_t * mgr, void * forwarder)
{
  /* Create statistics timer */
  Dispatcher *dispatcher = forwarder_GetDispatcher(forwarder);
  if (!dispatcher)
    return;

  mgr->forwarder = forwarder;

  // XXX used to be in message processor !
  mgr->timer = dispatcher_CreateTimer(dispatcher, /* repeat */ true,
          prefix_stats_mgr_tick, forwarder);
  if (!mgr->timer)
      return;
  struct timeval timeout = {STATS_INTERVAL / 1000, (STATS_INTERVAL % 1000) * 1000};
  dispatcher_StartTimer(dispatcher, mgr->timer, &timeout);
}

void
prefix_stats_mgr_finalize(prefix_stats_mgr_t * mgr)
{
    Forwarder * forwarder = mgr->forwarder;
  Dispatcher *dispatcher = forwarder_GetDispatcher(forwarder);
  if (!dispatcher)
    return;
  dispatcher_StopTimer(dispatcher, mgr->timer);
  dispatcher_DestroyTimerEvent(dispatcher, (PARCEventTimer**)&mgr->timer);
}


void
prefix_stats_on_retransmission(const prefix_stats_mgr_t * mgr, prefix_counters_t * counters,
        const nexthops_t * nexthops)
{
    connection_table_t * table = forwarder_GetConnectionTable(mgr->forwarder);
    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
#ifdef WITH_POLICY
        const Connection * conn = connection_table_at(table, nexthop);

        if (connection_HasTag(conn, POLICY_TAG_WIRED))
            counters->wired.num_losses++;
        if (connection_HasTag(conn, POLICY_TAG_WIFI))
            counters->wifi.num_losses++;
        if (connection_HasTag(conn, POLICY_TAG_CELLULAR))
            counters->cellular.num_losses++;
#endif /* WITH_POLICY */
        counters->all.num_losses++;
    });

}

#define UPDATE_TAG_STATS(TAG, NAME)                             \
do {                                                            \
        if (connection_HasTag(conn, TAG)) {                     \
            counters->NAME.num_packets++;                       \
            counters->NAME.num_bytes += msg_size;               \
            stats->NAME.latency = ALPHA * stats->NAME.latency + \
                    (1 - ALPHA) * (double)rtt;                  \
            counters->NAME.latency_idle = 0;                    \
        }                                                       \
} while(0)

/* Update statistic counters upon Data packet reception */
void
prefix_stats_on_data(const prefix_stats_mgr_t * mgr, prefix_stats_t * stats,
        prefix_counters_t * counters, const nexthops_t * nexthops,
        const msgbuf_t * msgbuf, Ticks rtt)
{
#ifdef WITH_POLICY
    Forwarder * forwarder = mgr->forwarder;
    connection_table_t * table = forwarder_GetConnectionTable(forwarder);
#endif /* WITH_POLICY */

    size_t msg_size = msgbuf_len(msgbuf);

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
#ifdef WITH_POLICY
        const Connection * conn = connection_table_at(table, nexthop);
        if (!conn)
            continue;

        UPDATE_TAG_STATS(POLICY_TAG_WIRED, wired);
        UPDATE_TAG_STATS(POLICY_TAG_WIFI, wifi);
        UPDATE_TAG_STATS(POLICY_TAG_CELLULAR, cellular);
#endif /* WITH_POLICY */
    });

    stats->all.latency = \
          ALPHA       * stats->all.latency + \
          (1 - ALPHA) * (double)rtt;
    counters->all.latency_idle = 0;
    counters->all.num_packets++;
    counters->all.num_bytes += msg_size;
}

void
prefix_stats_on_timeout(const prefix_stats_mgr_t * mgr, prefix_counters_t * counters,
        const nexthops_t * nexthops)
{
#ifdef WITH_POLICY
    connection_table_t * table = forwarder_GetConnectionTable(mgr->forwarder);

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
        const Connection * conn = connection_table_at(table, nexthop);
        if (!conn)
            continue;
        if (connection_HasTag(conn, POLICY_TAG_WIRED))
            counters->wired.num_losses++;
        if (connection_HasTag(conn, POLICY_TAG_WIFI))
            counters->wifi.num_losses++;
        if (connection_HasTag(conn, POLICY_TAG_CELLULAR))
            counters->cellular.num_losses++;
    });
#endif /* WITH_POLICY */

    counters->all.num_losses++;
}

#define UPDATE_TYPE(TYPE)                                               \
do {                                                                    \
    /* (a) throughput */                                                \
    if (counters->TYPE.num_bytes > 0) {                                 \
        throughput = counters->TYPE.num_bytes /                         \
                     (now - counters->last_update) ;                    \
        throughput = throughput * 8 / 1024;                             \
        if (throughput < 0)                                             \
            throughput = 0;                                             \
    } else {                                                            \
        throughput = 0;                                                 \
    }                                                                   \
    stats->TYPE.throughput = ALPHA * stats->TYPE.throughput +           \
            (1-ALPHA) * throughput;                                     \
                                                                        \
    /* (b) loss rate */                                                 \
    if ((counters->TYPE.num_losses > 0) &&                              \
            (counters->TYPE.num_packets > 0))  {                        \
        loss_rate = counters->TYPE.num_losses /                         \
                    counters->TYPE.num_packets;                         \
        loss_rate *= 100;                                               \
    } else {                                                            \
        loss_rate = 0;                                                  \
    }                                                                   \
    stats->TYPE.loss_rate = ALPHA * stats->TYPE.loss_rate +             \
            (1-ALPHA) * loss_rate;                                      \
                                                                        \
    /* (c) latency */                                                   \
    counters->TYPE.latency_idle++;                                      \
    if (counters->TYPE.latency_idle > 1)                                \
        stats->TYPE.latency = 0;                                        \
                                                                        \
    /* (d) Reset counters */                                            \
    counters->TYPE.num_bytes = 0;                                       \
    counters->TYPE.num_losses = 0;                                      \
    counters->TYPE.num_packets = 0;                                     \
} while(0)

void
prefix_stats_update(prefix_stats_t * stats, prefix_counters_t * counters, uint64_t now)
{
    double throughput;
    double loss_rate;

    if (now == counters->last_update)
        return;

#ifdef WITH_POLICY
    UPDATE_TYPE(wired);
    UPDATE_TYPE(wifi);
    UPDATE_TYPE(cellular);
#endif /* WITH_POLICY */
    UPDATE_TYPE(all);

    counters->last_update = now;

}

#endif /* WITH_PREFIX_STATS */
