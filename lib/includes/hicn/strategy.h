/*
 * copyright (c) 2017-2019 cisco and/or its affiliates.
 * licensed under the apache license, version 2.0 (the "license");
 * you may not use this file except in compliance with the license.
 * you may obtain a copy of the license at:
 *
 *     http://www.apache.org/licenses/license-2.0
 *
 * unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "as is" basis,
 * without warranties or conditions of any kind, either express or implied.
 * see the license for the specific language governing permissions and
 * limitations under the license.
 */

/**
 * \file strategy.h
 * \brief Forwarding strategy concept definition
 */
#ifndef HICN_STRATEGY_H
#define HICN_STRATEGY_H

#define MAXSZ_STRATEGY_NAME 255

/* How to retrieve that from the forwarder ? */
#define foreach_hicn_strategy_name      \
    _(UNDEFINED)                        \
    _(LOAD_BALANCER)                    \
    _(RANDOM)                           \
    _(LOW_LATENCY)                      \
    _(N)

#define MAXSZ_HICN_STRATEGY_NAME_ 13
#define MAXSZ_HICN_STRATEGY_NAME MAXSZ_HICN_STRATEGY_NAME_ + 1

typedef enum {
#define _(x) HICN_STRATEGY_ ## x,
    foreach_hicn_strategy_name
#undef _
} hicn_strategy_t;

extern const char * HICN_STRATEGY_STR[];

int hicn_strategy_get_by_name(const char * name, hicn_strategy_t * strategy);

#define HICN_STRATEGY_IS_VALID(s) ((s > HICN_STRATEGY_UNDEFINED) && (HICN_STRATEGY_N))

#endif /* HICN_STRATEGY_H */
