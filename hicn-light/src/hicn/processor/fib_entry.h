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
 * @file fib_entry.h
 * @brief A forwarding entry in the FIB table
 *
 * A Forwarding Information Base (FIB) entry (fib_entry_t) is a
 * set of nexthops for a name.  It also indicates the forwarding strategy.
 *
 * Each nexthop contains the ConnectionId assocaited with it.  This could be
 * something specific like a MAC address or point-to-point tunnel.  Or, it
 * could be something general like a MAC group address or ip multicast overlay.
 *
 * See strategy.h for a description of forwarding strategies.
 * In short, a strategy is the algorithm used to select one or more nexthops
 * from the set of available nexthops.
 *
 * Each nexthop also contains a void* to a forwarding strategy data container.
 * This allows a strategy to keep proprietary information about each nexthop.
 *
 *
 */

#ifndef fib_entry_h
#define fib_entry_h

#include <hicn/core/name.h>
#include <hicn/base/strategy.h>
#include <hicn/base/msgbuf.h>
#include <hicn/base/nexthops.h>
#include <hicn/base/prefix_stats.h>
#include <hicn/utils/commands.h> // strategy type

#ifdef WITH_MAPME
#include <parc/algol/parc_EventTimer.h>
#include <parc/algol/parc_Iterator.h>
#endif /* WITH_MAPME */

typedef struct {
  Name *name;
  unsigned refcount;
  nexthops_t nexthops;
  strategy_entry_t strategy;

  const void * forwarder;

#ifdef WITH_POLICY
  policy_t policy;
#endif /* WITH_POLICY */

  prefix_counters_t prefix_counters;
  prefix_stats_t prefix_stats;

#ifdef WITH_MAPME
  /* In case of no multipath, this stores the previous decision taken by policy. As the list of nexthops is not expected to change, we can simply store the flags */
  uint_fast32_t prev_nexthops_flags;
  void *userData;
  void (*userDataRelease)(void **userData);
#endif /* WITH_MAPME */
} fib_entry_t;

#define _fib_entry_var(x) _fib_entry_##x

#define fib_entry_strategy_type(fib_entry) ((fib_entry)->strategy.type)

#define fib_entry_nexthops(fib_entry) (&(fib_entry)->nexthops)
#define fib_entry_nexthops_len(fib_entry) (nexthops_len(&(fib_entry)->nexthops))
#define fib_entry_nexthops_curlen(fib_entry) (nexthops_curlen(&(fib_entry)->nexthops))
#define fib_entry_get_nexthop(fib_entry, i) ((fib_entry)->nexthops.elts[i])
#define fib_entry_foreach_nexthop(fib_entry, nexthop, BODY)             \
    nexthops_foreach(fib_entry->nexthops, BODY)

#define fib_entry_nexthops_changed(fib_entry) \
    ((fib_entry)->prev_nexthops_flags == fib_entry_nexthops(fib_entry)->flags)

#define fib_entry_set_prev_nexthops(fib_entry) \
    ((fib_entry)->prev_nexthops_flags = fib_entry_nexthops(fib_entry)->flags)

struct forwarder;
fib_entry_t *fib_entry_Create(Name *name, strategy_type_t strategy_type,
        strategy_options_t * strategy_options, const struct forwarder * table);

/**
 * Decrements the reference count by one, and destroys the memory after last
 * release
 *
 */
void fib_entry_Release(fib_entry_t **fib_entryPtr);

/**
 * Returns a reference counted copy of the fib entry
 *
 * The reference count is increased by one.  The returned value must be
 * released via fibEnty_Release().
 *
 * @param [in] fib_entry An allocated fib_entry_t
 *
 * @return non-null A reference counted copy of the fib_entry
 *
 */
fib_entry_t *fib_entry_Acquire(const fib_entry_t *fib_entry);

void fib_entry_SetStrategy(fib_entry_t *fib_entry,
        strategy_type_t strategy_type, strategy_options_t * strategy_options);

void fib_entry_nexthops_add(fib_entry_t * fib_entry, unsigned nexthop);

void fib_entry_nexthops_remove(fib_entry_t * fib_entry, unsigned nexthop);

size_t fib_entry_NexthopCount(const fib_entry_t *fib_entry);

/**
 * @function fib_entry_GetNexthops
 * @abstract Returns the nexthop set of the FIB entry.  You must Acquire if it
 * will be saved.
 * @discussion
 *   Returns the next hop set for the FIB entry.
 */
const nexthops_t * fib_entry_GetNexthops(const fib_entry_t *fib_entry);

const nexthops_t * fib_entry_GetNexthopsFromForwardingStrategy(
    fib_entry_t *fib_entry, const msgbuf_t *interestMessage, bool is_retransmission);

void fib_entry_ReceiveObjectMessage(fib_entry_t *fib_entry, const nexthops_t * nexthops,
        const msgbuf_t * objectMessage, Ticks pitEntryCreation,
        Ticks objReception);

#ifdef WITH_POLICY
policy_t fib_entry_get_policy(const fib_entry_t *fib_entry);
void fib_entry_ReconsiderPolicy(fib_entry_t *fib_entry);
void fib_entry_SetPolicy(fib_entry_t *fib_entry, policy_t policy);
void fib_entry_UpdateStats(fib_entry_t *fib_entry, uint64_t now);
#endif /* WITH_POLICY */

nexthops_t * fib_entry_GetAvailableNextHops(fib_entry_t *fib_entry,
    unsigned in_connection, nexthops_t * new_nexthops);
void fib_entry_OnTimeout(fib_entry_t *fib_entry, const nexthops_t *egressId);
const nexthops_t * fib_entry_GetNexthopsFromForwardingStrategy(
    fib_entry_t *fib_entry, const msgbuf_t *interestMessage, bool is_retransmission);

#if 0
// XXX TODO reconsider both
strategy_type_t fib_entry_GetFwdStrategyType(const fib_entry_t *fib_entry);
StrategyImpl *fib_entry_GetFwdStrategy(const fib_entry_t *fib_entry);
#endif

/**
 * @function fib_entry_GetPrefix
 * @abstract Returns a copy of the prefix.
 * @return A reference counted copy that you must destroy
 */
Name *fib_entry_GetPrefix(const fib_entry_t *fib_entry);

#ifdef WITH_MAPME

/**
 * @function fib_entry_getUserData
 * @abstract Returns user data associated to the FIB entry.
 * @param [in] fib_entry - Pointer to the FIB entry.
 * @return User data as a void pointer
 */
void *fib_entry_getUserData(const fib_entry_t *fib_entry);

/**
 * @function fib_entry_getUserData
 * @abstract Associates user data and release callback to a FIB entry.
 * @param [in] fib_entry - Pointer to the FIB entry.
 * @param [in] userData - Generic pointer to user data
 * @param [in@ userDataRelease - Callback used to release user data upon change
 *       of FIB entry removal.
 */
void fib_entry_setUserData(fib_entry_t *fib_entry, const void *userData,
                          void (*userDataRelease)(void **));

#endif /* WITH_MAPME */

#endif  // fib_entry_h
