
#ifndef HICNLIGHT_POLICY_STATS_H
#define HICNLIGHT_POLICY_STATS_H

#ifdef WITH_POLICY_STATS

#include <hicn/policy.h>
#include "../base/loop.h"

typedef struct policy_stats_mgr_s {
  void* forwarder;
  event_t* timer;
} policy_stats_mgr_t;

#if 0

/* PER-INTERFACE POLICY STATS */

typedef struct {
    float throughput;
    float latency;
    float loss_rate;
} interface_stats_t;

/* POLICY STATS */

typedef struct {
    interface_stats_t wired;
    interface_stats_t wifi;
    interface_stats_t cellular;
    interface_stats_t all;
} policy_stats_t;

typedef struct {
    uint32_t num_packets;
    uint32_t num_bytes;
    uint32_t num_losses;
    uint32_t latency_idle;
} interface_counters_t;

typedef struct {
    interface_counters_t wired;
    interface_counters_t wifi;
    interface_counters_t cellular;
    interface_counters_t all;
    uint64_t last_update;
} policy_counters_t;

#define INTERFACE_STATS_EMPTY \
  (interface_stats_t) { .throughput = 0, .latency = 0, .loss_rate = 0, }

#define POLICY_STATS_EMPTY                                           \
  (policy_stats_t) {                                                 \
    .wired = INTERFACE_STATS_EMPTY, .wifi = INTERFACE_STATS_EMPTY,   \
    .cellular = INTERFACE_STATS_EMPTY, .all = INTERFACE_STATS_EMPTY, \
  }

#define INTERFACE_COUNTERS_EMPTY                                          \
  (interface_counters_t) {                                                \
    .num_packets = 0, .num_bytes = 0, .num_losses = 0, .latency_idle = 0, \
  }

#define POLICY_COUNTERS_EMPTY                                              \
  (policy_counters_t) {                                                    \
    .wired = INTERFACE_COUNTERS_EMPTY, .wifi = INTERFACE_COUNTERS_EMPTY,   \
    .cellular = INTERFACE_COUNTERS_EMPTY, .all = INTERFACE_COUNTERS_EMPTY, \
    .last_update = 0,                                                      \
  }
#endif

int policy_stats_mgr_initialize(policy_stats_mgr_t* mgr, void* forwarder);

void policy_stats_mgr_finalize(policy_stats_mgr_t* mgr);

void policy_stats_on_retransmission(const policy_stats_mgr_t* mgr,
                                    policy_counters_t* countrs,
                                    const nexthops_t* nexthops);

void policy_stats_on_data(const policy_stats_mgr_t* mgr, policy_stats_t* stats,
                          policy_counters_t* counters,
                          const nexthops_t* nexthops, const msgbuf_t* msgbuf,
                          Ticks rtt);

void policy_stats_on_timeout(const policy_stats_mgr_t* mgr,
                             policy_counters_t* counters,
                             const nexthops_t* nexthops);

void policy_stats_update(policy_stats_t* stats, policy_counters_t* counters,
                         uint64_t now);

#endif /* WITH_POLICY_STATS */

#endif /* HICNLIGHT_POLICY_STATS_H */
