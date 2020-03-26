/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
 * \file policy.h
 * \brief Policy description
 */
#ifndef HICN_POLICY_H
#define HICN_POLICY_H

#ifndef _WIN32
#include <netinet/in.h> // INET*_ADDRSTRLEN
#else
#include <hicn/util/win_portability.h>
#endif
#include <string.h> // strcasecmp
#include <hicn/util/token.h>

/* POLICY TAG */

#define foreach_policy_tag      \
    /* Interface type */        \
    _(WIRED, 'E')               \
    _(WIFI, 'W')                \
    _(CELLULAR, 'C')            \
    /* QoS */                   \
    _(BEST_EFFORT, 'b')         \
    _(REALTIME, 'r')            \
    _(MULTIPATH, 'M')           \
    /* Security */              \
    _(TRUSTED, 'T')

typedef enum {
#define _(x, y) POLICY_TAG_ ## x,
foreach_policy_tag
#undef _
    POLICY_TAG_N
} policy_tag_t;

#define MAXSZ_POLICY_TAG_ 11
#define MAXSZ_POLICY_TAG MAXSZ_POLICY_TAG_ + 1

extern const char * policy_tag_str[];
extern const char policy_tag_short_str[];

static inline
policy_tag_t
policy_tag_from_str(const char * str)
{
#define _(x, y) if (strcasecmp(str, policy_tag_str[POLICY_TAG_ ## x] ) == 0) { return POLICY_TAG_ ## x; } else
foreach_policy_tag
#undef _
    return POLICY_TAG_N;
}

/* POLICY_TAGS */

typedef int policy_tags_t;

static inline
void policy_tags_add(policy_tags_t * tags, policy_tag_t tag)
{
    *tags |= (1 << tag);
}

static inline
void policy_tags_remove(policy_tags_t * tags, policy_tag_t tag)
{
    *tags &= ~(1 << tag);
}

static inline
int policy_tags_has(policy_tags_t tags, policy_tag_t tag)
{
    return tags & (1 << tag);
}

static inline
void policy_tags_union(policy_tags_t * tags, policy_tags_t * tags_to_union)
{
#define _(x, y) *tags |= policy_tags_has(*tags_to_union, POLICY_TAG_ ## x) ? (1 << POLICY_TAG_ ## x) : 0;
foreach_policy_tag
#undef _
}

#define POLICY_TAGS_EMPTY 0

static inline
int
policy_tags_snprintf(char * s, size_t size, policy_tags_t tags)
{
#define _(x, y) s[POLICY_TAG_ ## x] = policy_tags_has(tags, POLICY_TAG_ ## x) ? y : '.';
foreach_policy_tag
#undef _
    s[POLICY_TAG_N] = '\0';
    return POLICY_TAG_N + 1;
}

#define MAXSZ_POLICY_TAGS_ POLICY_TAG_N + 1
#define MAXSZ_POLICY_TAGS MAXSZ_POLICY_TAGS_ + 1

/* POLICY STATE */

/* TODO vs. weight */

#define foreach_policy_state    \
    _(NEUTRAL)                  \
    _(REQUIRE)                  \
    _(PREFER)                   \
    _(AVOID)                    \
    _(PROHIBIT)                 \
    _(N)

typedef enum {
#define _(x) POLICY_STATE_ ## x,
foreach_policy_state
#undef _
} policy_state_t;

#define MAXSZ_POLICY_STATE_ 8
#define MAXSZ_POLICY_STATE MAXSZ_POLICY_STATE_ + 1

extern const char * policy_state_str[];


/* POLICY TAG STATE */

typedef struct {
    policy_state_t state;
    uint8_t disabled;
} policy_tag_state_t;

#define MAXSZ_POLICY_TAG_STATE_ 8
#define MAXSZ_POLICY_TAG_STATE MAXSZ_POLICY_TAG_STATE_ + 1

int policy_tag_state_snprintf(char * s, size_t size, const policy_tag_state_t * tag_state);


/* INTERFACE STATS */

typedef struct {
    float throughput;
    float latency;
    float loss_rate;
} interface_stats_t;

#define INTERFACE_STATS_NONE {                          \
    .throughput = 0,                                    \
    .latency = 0,                                       \
    .loss_rate = 0,                                     \
}


/* POLICY STATS */

typedef struct {
    interface_stats_t wired;
    interface_stats_t wifi;
    interface_stats_t cellular;
    interface_stats_t all;
} policy_stats_t;

#define POLICY_STATS_NONE {                     \
    .wired    = INTERFACE_STATS_NONE,           \
    .wifi     = INTERFACE_STATS_NONE,           \
    .cellular = INTERFACE_STATS_NONE,           \
    .all      = INTERFACE_STATS_NONE,           \
}

typedef struct {
    uint32_t num_packets;
    uint32_t num_bytes;
    uint32_t num_losses;
    uint32_t latency_idle;
} interface_counters_t;

#define INTERFACE_COUNTERS_NONE {               \
    .num_packets = 0,                           \
    .num_bytes = 0,                             \
    .num_losses = 0,                            \
    .latency_idle = 0,                          \
}

typedef struct {
    interface_counters_t wired;
    interface_counters_t wifi;
    interface_counters_t cellular;
    interface_counters_t all;
    uint64_t last_update;
} policy_counters_t;

#define POLICY_COUNTERS_NONE (policy_counters_t) {      \
    .wired    = INTERFACE_COUNTERS_NONE,                \
    .wifi     = INTERFACE_COUNTERS_NONE,                \
    .cellular = INTERFACE_COUNTERS_NONE,                \
    .all      = INTERFACE_COUNTERS_NONE,                \
    .last_update = 0,                                   \
}

/* POLICY */

#define APP_NAME_LEN 128

typedef struct {
    char app_name[APP_NAME_LEN];
    policy_tag_state_t tags[POLICY_TAG_N];
    policy_stats_t stats;
} policy_t;

static const policy_t POLICY_NONE = {
    .app_name = { 0 },
    .tags = {
#define _(x, y) [POLICY_TAG_ ## x] = { POLICY_STATE_NEUTRAL, 0 },
foreach_policy_tag
#undef _
    },
    .stats = POLICY_STATS_NONE,
};


/* POLICY DESCRIPTION */

#define PFX_STRLEN 4 /* eg. /128 */

typedef struct {
    int family;
    union {
        char ipv4_prefix[INET_ADDRSTRLEN + PFX_STRLEN];
        char ipv6_prefix[INET6_ADDRSTRLEN + PFX_STRLEN];
    };
    policy_t policy;
} policy_description_t;

#endif /* HICN_POLICY_H */
