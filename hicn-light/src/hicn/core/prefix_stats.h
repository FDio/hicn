
#ifndef HICNLIGHT_PREFIX_STATS_H
#define HICNLIGHT_PREFIX_STATS_H

#ifdef WITH_PREFIX_STATS

typedef struct prefix_stats_mgr_s {
    void * forwarder;
    int timer_fd;
} prefix_stats_mgr_t;


/* PER-INTERFACE PREFIX STATS */

typedef struct {
    float throughput;
    float latency;
    float loss_rate;
} interface_stats_t;

/* PREFIX STATS */

typedef struct {
    interface_stats_t wired;
    interface_stats_t wifi;
    interface_stats_t cellular;
    interface_stats_t all;
} prefix_stats_t;

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
} prefix_counters_t;

#define INTERFACE_STATS_EMPTY (interface_stats_t) {             \
    .throughput = 0,                                            \
    .latency = 0,                                               \
    .loss_rate = 0,                                             \
}

#define PREFIX_STATS_EMPTY (prefix_stats_t) {                   \
    .wired    = INTERFACE_STATS_EMPTY,                          \
    .wifi     = INTERFACE_STATS_EMPTY,                          \
    .cellular = INTERFACE_STATS_EMPTY,                          \
    .all      = INTERFACE_STATS_EMPTY,                          \
}

#define INTERFACE_COUNTERS_EMPTY (interface_counters_t) {       \
    .num_packets = 0,                                           \
    .num_bytes = 0,                                             \
    .num_losses = 0,                                            \
    .latency_idle = 0,                                          \
}

#define PREFIX_COUNTERS_EMPTY (prefix_counters_t) {             \
    .wired    = INTERFACE_COUNTERS_EMPTY,                       \
    .wifi     = INTERFACE_COUNTERS_EMPTY,                       \
    .cellular = INTERFACE_COUNTERS_EMPTY,                       \
    .all      = INTERFACE_COUNTERS_EMPTY,                       \
    .last_update = 0,                                           \
}

int prefix_stats_mgr_initialize(prefix_stats_mgr_t * mgr, void * forwarder);

void prefix_stats_mgr_finalize(prefix_stats_mgr_t * mgr);

void prefix_stats_on_retransmission(const prefix_stats_mgr_t * mgr,
        prefix_counters_t * countrs, const nexthops_t * nexthops);

void prefix_stats_on_data(const prefix_stats_mgr_t * mgr, prefix_stats_t * stats,
        prefix_counters_t * counters, const nexthops_t * nexthops,
        const msgbuf_t * msgbuf, Ticks rtt);

void prefix_stats_on_timeout(const prefix_stats_mgr_t * mgr, prefix_counters_t * counters,
        const nexthops_t * nexthops);

void prefix_stats_update(prefix_stats_t * stats, prefix_counters_t * counters, uint64_t now);

#endif /* WITH_PREFIX_STATS */

#endif /* HICNLIGHT_PREFIX_STATS_H */
