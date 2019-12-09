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

#include <netinet/in.h> // INET*_ADDRSTRLEN
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

/* POLICY */

#define APP_NAME_LEN 128

typedef struct {
    char app_name[APP_NAME_LEN];
    policy_tag_state_t tags[POLICY_TAG_N];
} policy_t;

static const policy_t POLICY_NONE = {
    .app_name = { 0 },
    .tags = {
#define _(x, y) [POLICY_TAG_ ## x] = { POLICY_STATE_NEUTRAL, 0 },
foreach_policy_tag
#undef _
    },
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
