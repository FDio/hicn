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

#include <stdio.h>

#include <hicn/hicn-light/config.h>
#include <hicn/core/fib_entry.h>
#include <hicn/core/strategy.h>

#ifdef WITH_MAPME
#include <hicn/core/ticks.h>
#endif /* WITH_MAPME */

#ifdef WITH_POLICY
#include <hicn/core/forwarder.h>
#include <hicn/policy.h>

#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */

#endif /* WITH_POLICY */

#ifdef WITH_POLICY_STATS
#include <hicn/core/policy_stats.h>
#endif /* WITH_POLICY_STATS */

fib_entry_t *fib_entry_create(const hicn_prefix_t *prefix,
                              strategy_type_t strategy_type,
                              strategy_options_t *strategy_options,
                              const forwarder_t *forwarder) {
  assert(prefix);
  /*
   * For tests, we allow forwarder to be NULL, some
   * functions cannot be called but otherwise we need a main loop, etc.
   */
  // assert(forwarder);

  fib_entry_t *entry = malloc(sizeof(fib_entry_t));
  if (!entry) goto ERR_MALLOC;

  memset(entry, 0, sizeof(*entry));
  hicn_prefix_copy(&entry->prefix, prefix);
  entry->nexthops = NEXTHOPS_EMPTY;

  fib_entry_add_strategy_options(entry, STRATEGY_TYPE_BESTPATH, NULL);
  fib_entry_add_strategy_options(entry, STRATEGY_TYPE_REPLICATION, NULL);
  fib_entry_set_strategy(entry, strategy_type, strategy_options);

#ifdef WITH_MAPME
  entry->user_data = NULL;
  entry->user_data_release = NULL;
#endif /* WITH_MAPME */

  entry->forwarder = forwarder;

#ifdef WITH_POLICY
  entry->policy = POLICY_EMPTY;
#endif /* WITH_POLICY */

#ifdef WITH_POLICY_STATS
  entry->policy_stats = POLICY_STATS_EMPTY;
  entry->policy_counters = POLICY_COUNTERS_EMPTY;
#endif /* WITH_POLICY_STATS */

  return entry;

ERR_MALLOC:
  return NULL;
}

void fib_entry_free(fib_entry_t *entry) {
  assert(entry);
#ifdef WITH_MAPME
  if (entry->user_data) entry->user_data_release(&entry->user_data);
#endif /* WITH_MAPME */
  free(entry);
}

void fib_entry_add_strategy_options(fib_entry_t *entry,
                                    strategy_type_t strategy_type,
                                    strategy_options_t *strategy_options) {
  // for the moment only the best path and replication strategies support
  // strategy options return for the other strategyes
  if (strategy_type != STRATEGY_TYPE_BESTPATH &&
      strategy_type != STRATEGY_TYPE_REPLICATION)
    return;

  if (!strategy_options) {
    if (strategy_type == STRATEGY_TYPE_BESTPATH) {
      entry->strategy.options.bestpath.local_prefixes = NULL;
    } else {
      entry->strategy.options.replication.local_prefixes = NULL;
    }
    return;
  }

  local_prefixes_t *new_prefixes;
  local_prefixes_t *curr_prefixes;

  if (strategy_type == STRATEGY_TYPE_BESTPATH) {
    new_prefixes = strategy_options->bestpath.local_prefixes;
    curr_prefixes = entry->strategy.options.bestpath.local_prefixes;

    if (!curr_prefixes) {
      entry->strategy.options.bestpath.local_prefixes = create_local_prefixes();
      curr_prefixes = entry->strategy.options.bestpath.local_prefixes;
    }
  } else {
    new_prefixes = strategy_options->replication.local_prefixes;
    curr_prefixes = entry->strategy.options.replication.local_prefixes;

    if (!curr_prefixes) {
      entry->strategy.options.replication.local_prefixes =
          create_local_prefixes();
      curr_prefixes = entry->strategy.options.replication.local_prefixes;
    }
  }

  local_prefixes_add_prefixes(curr_prefixes, new_prefixes);
}

void fib_entry_set_strategy(fib_entry_t *entry, strategy_type_t strategy_type,
                            strategy_options_t *strategy_options) {
  // Default strategy if undefined
  if (!STRATEGY_TYPE_VALID(strategy_type)) strategy_type = STRATEGY_TYPE_RANDOM;

  if (entry->strategy.type == strategy_type) {  // startegy alredy set
    if (strategy_type != STRATEGY_TYPE_BESTPATH) {
      return;  // nothing to do
    } else {
      strategy_initialize(&entry->strategy, entry->forwarder);
      return;
    }
  }

  entry->strategy.type = strategy_type;
  if (strategy_options) entry->strategy.options = *strategy_options;

  strategy_initialize(&entry->strategy, entry->forwarder);
}

/*
 * Filters the set of nexthops passed as parameters (and not the one stored in
 * the FIB entry
 */
nexthops_t *fib_entry_filter_nexthops(fib_entry_t *entry, nexthops_t *nexthops,
                                      unsigned ingress_id, bool prefer_local) {
  assert(entry);
  assert(nexthops);

  nexthops_reset(nexthops);

  // DEBUG("[fib_entry_filter_nexthops] num=%d/%d ingress_id=%d",
  //         nexthops_get_curlen(nexthops), nexthops_get_len(nexthops),
  //         ingress_id);

  /* Filter out ingress, down & administrative down faces */
  const connection_table_t *table =
      forwarder_get_connection_table(entry->forwarder);
  connection_t *conn;
  uint_fast32_t flags;

  hicn_policy_t policy = fib_entry_get_policy(entry);

  nexthops_enumerate(nexthops, i, nexthop, {
    conn = connection_table_at(table, nexthop);
    nexthops_disable_if(nexthops, i, nexthop == ingress_id);
    nexthops_disable_if(nexthops, i,
                        (connection_get_admin_state(conn) == FACE_STATE_DOWN));
    nexthops_disable_if(nexthops, i,
                        (connection_get_state(conn) == FACE_STATE_DOWN));
  });

  // DEBUG("After pruning, num=%d/%d", nexthops_get_curlen(nexthops),
  // nexthops_get_len(nexthops));

  if (prefer_local) {
    /* Backup flags and cur_len*/
    flags = nexthops->flags;
    size_t cur_len = nexthops_get_curlen(nexthops);

    /* Filter local */
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i, (!connection_is_local(conn)));
    });

    /* Local faces have priority */
    if (nexthops_get_curlen(nexthops) > 0) return nexthops;

    nexthops->flags = flags;
    nexthops->cur_elts = cur_len;
  }

  /* Filter out local */
  nexthops_enumerate(nexthops, i, nexthop, {
    conn = connection_table_at(table, nexthop);
    nexthops_disable_if(nexthops, i, (connection_is_local(conn)));

#ifdef WITH_POLICY
    /* Policy filtering : next hops */
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_REQUIRE) &&
            (!connection_has_tag(conn, POLICY_TAG_WIRED)));
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PROHIBIT) &&
            (connection_has_tag(conn, POLICY_TAG_WIRED)));
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_REQUIRE) &&
            (!connection_has_tag(conn, POLICY_TAG_WIFI)));
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PROHIBIT) &&
            (connection_has_tag(conn, POLICY_TAG_WIFI)));
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_REQUIRE) &&
            (!connection_has_tag(conn, POLICY_TAG_CELLULAR)));
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PROHIBIT) &&
            (connection_has_tag(conn, POLICY_TAG_CELLULAR)));
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE) &&
            (!connection_has_tag(conn, POLICY_TAG_TRUSTED)));
    nexthops_disable_if(
        nexthops, i,
        (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_PROHIBIT) &&
            (connection_has_tag(conn, POLICY_TAG_TRUSTED)));
#endif /* WITH_POLICY */
  });

  if (nexthops_get_curlen(nexthops) == 0) {
    DEBUG("After REQUIRE/PROHIBIT pruning, num=%d/%d",
          nexthops_get_curlen(nexthops), nexthops_get_len(nexthops));
    return nexthops;
  }

  /* We have at least one matching next hop, implement heuristic */

#ifdef WITH_POLICY
  /*
   * As VPN connections might trigger duplicate uses of one interface, we start
   * by filtering out interfaces based on trust status.
   */
  flags = nexthops->flags;

  if ((policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE) ||
      (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_PREFER)) {
    /* Try to filter out NON TRUSTED faces */
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          (!connection_has_tag(conn, POLICY_TAG_TRUSTED)));
    });

    if ((nexthops_get_curlen(nexthops) == 0) &&
        (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE)) {
      return nexthops;
    }

  } else {
    /* Try to filter out TRUSTED faces */
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          (connection_has_tag(conn, POLICY_TAG_TRUSTED)));
    });
  }

  if (nexthops_get_curlen(nexthops) == 0) nexthops->flags = flags;

  /* Other preferences */
  if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_AVOID) {
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          connection_has_tag(conn, POLICY_TAG_WIRED));
    });
    if (nexthops_get_curlen(nexthops) == 0) nexthops->flags = flags;
  }
  if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_AVOID) {
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          connection_has_tag(conn, POLICY_TAG_WIFI));
    });
    if (nexthops_get_curlen(nexthops) == 0) nexthops->flags = flags;
  }
  if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_AVOID) {
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          connection_has_tag(conn, POLICY_TAG_CELLULAR));
    });
    if (nexthops_get_curlen(nexthops) == 0) nexthops->flags = flags;
  }

  if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PREFER) {
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          !connection_has_tag(conn, POLICY_TAG_WIRED));
    });
    if (nexthops_get_curlen(nexthops) == 0) nexthops->flags = flags;
  }
  if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PREFER) {
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          !connection_has_tag(conn, POLICY_TAG_WIFI));
    });
    if (nexthops_get_curlen(nexthops) == 0) nexthops->flags = flags;
  }
  if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PREFER) {
    nexthops_enumerate(nexthops, i, nexthop, {
      conn = connection_table_at(table, nexthop);
      nexthops_disable_if(nexthops, i,
                          !connection_has_tag(conn, POLICY_TAG_CELLULAR));
    });
    if (nexthops_get_curlen(nexthops) == 0) nexthops->flags = flags;
  }
// XXX backup curlen ???
#endif /* WITH_POLICY */

  DEBUG("[fib_entry_filter_nexthops] before face priority num=%d/%d",
        nexthops_get_curlen(nexthops), nexthops_get_len(nexthops));

  /* Priority */
  uint32_t max_priority = 0;
  nexthops_foreach(nexthops, nexthop, {
    conn = connection_table_at(table, nexthop);
    uint32_t priority = connection_get_priority(conn);
    if (priority > max_priority) max_priority = priority;
  });
  nexthops_enumerate(nexthops, i, nexthop, {
    conn = connection_table_at(table, nexthop);
    nexthops_disable_if(nexthops, i,
                        connection_get_priority(conn) < max_priority);
  });

  DEBUG("[fib_entry_filter_nexthops] result num=%d/%d",
        nexthops_get_curlen(nexthops), nexthops_get_len(nexthops));

  /* Nexthop priority */

  /*
   * Filter out nexthops with lowest strategy priority.
   * Initializing at 0 allows to disable nexthops with a negative priority
   */
  max_priority = 0;
  nexthops_enumerate(nexthops, i, nexthop, {
    (void)nexthop;
    int priority = nexthops->state[i].priority;
    if (priority > max_priority) max_priority = priority;
  });
  nexthops_enumerate(nexthops, i, nexthop, {
    int priority = nexthops->state[i].priority;
    nexthops_disable_if(nexthops, i, (priority < max_priority));
  });

  /*
   * If multipath is disabled, we don't offer much choice to the forwarding
   * strategy, but still go through it for accounting purposes.
   */
  if ((policy.tags[POLICY_TAG_MULTIPATH].state == POLICY_STATE_PROHIBIT) ||
      (policy.tags[POLICY_TAG_MULTIPATH].state == POLICY_STATE_AVOID)) {
    DEBUG(
        "[fib_entry_get_nexthops_from_strategy] select single nexthops due to "
        "multipath policy");
    nexthops_select_first(nexthops);
  }

  return nexthops;
}

/*
 * Retrieve all candidate nexthops for sending mapme updates == all non local
 * connections. We don't apply the policy at this stage.
 */
nexthops_t *fib_entry_get_mapme_nexthops(fib_entry_t *entry,
                                         nexthops_t *new_nexthops) {
  assert(new_nexthops);

  const connection_table_t *table =
      forwarder_get_connection_table(entry->forwarder);

  /* We create a nexthop structure based on connections */
  // XXX This should be done close to where it is needed
  connection_t *connection;
  connection_table_foreach(table, connection, {
    if (connection_is_local(connection)) continue;
    new_nexthops->elts[nexthops_get_len(new_nexthops)] =
        connection_table_get_connection_id(table, connection);
    nexthops_inc(new_nexthops);
  });

  return new_nexthops;
}

/*
 * Update available next hops following policy update.
 *
 * The last nexthop parameter is only used if needed, otherwise the pointer to
 * fib entry is returned to avoid an useless copy
 */
nexthops_t *fib_entry_get_available_nexthops(fib_entry_t *entry,
                                             unsigned ingress_id,
                                             nexthops_t *new_nexthops) {
  // DEBUG("[fib_entry_get_available_nexthops]");

  connection_table_t *table = forwarder_get_connection_table(entry->forwarder);

  /*
   * Give absolute preference to local faces, with no policy, unless
   * ingress_id == ~0, which means we are searching faces on which to
   * advertise our prefix
   */
  if (ingress_id == ~0) {
    assert(new_nexthops);
    /* We create a nexthop structure based on connections */
    // XXX This should be done close to where it is needed
    connection_t *connection;
    connection_table_foreach(table, connection, {
      if (connection_is_local(connection)) continue;
      new_nexthops->elts[nexthops_get_len(new_nexthops)] =
          (unsigned int)connection_table_get_connection_id(table, connection);
      nexthops_inc(new_nexthops);
    });

#ifdef WITH_POLICY
    return fib_entry_filter_nexthops(entry, new_nexthops, ingress_id, false);
#else
    return new_nexthops;
#endif
  }

#ifdef WITH_POLICY
  return fib_entry_filter_nexthops(entry, fib_entry_get_nexthops(entry),
                                   ingress_id, true);
#else
  return fib_entry_get_nexthops(entry);
#endif
}

#ifdef WITH_POLICY

hicn_policy_t fib_entry_get_policy(const fib_entry_t *entry) {
  return entry->policy;
}

void fib_entry_set_policy(fib_entry_t *entry, hicn_policy_t policy) {
  INFO("fib_entry_set_policy");
  entry->policy = policy;

  forwarder_on_route_event(entry->forwarder, entry);

  // XXX generic mechanism to perform a mapme update
#if 0
#ifdef WITH_MAPME
  /*
   * Skip entries that do not correspond to a producer ( / have a locally
   * served prefix / have no local connection as next hop)
   */
  if (!fib_entry_has_local_nexthop(entry)) return;
  mapme_t *mapme = forwarder_get_mapme(entry->forwarder);
#endif /* WITH_MAPME */
#endif
}

#endif /* WITH_POLICY */

void fib_entry_nexthops_add(fib_entry_t *entry, unsigned nexthop) {
  /*
   * Nexthop is added to both:
   *  - fib_entry: it is added to the nexthops_t struct, in the elts array.
   *  - strategy: only used to eventually initialize internal state, might be
   *  empty like in the random strategy.
   */
  off_t id = nexthops_add(&entry->nexthops, nexthop);
  strategy_add_nexthop(&entry->strategy, &entry->nexthops, id);
}

void fib_entry_nexthops_remove(fib_entry_t *entry, unsigned nexthop) {
  off_t id = nexthops_remove(&entry->nexthops, nexthop);
  strategy_remove_nexthop(&entry->strategy, &entry->nexthops, id);
}

nexthops_t *fib_entry_get_nexthops_from_strategy(fib_entry_t *entry,
                                                 const msgbuf_t *msgbuf,
                                                 bool is_retransmission) {
  assert(entry);
  assert(msgbuf);

  // DEBUG("[fib_entry_get_nexthops_from_strategy]");

  const policy_stats_mgr_t *mgr =
      forwarder_get_policy_stats_mgr(entry->forwarder);
  assert(mgr);

  /* Filtering */
  nexthops_t *nexthops = fib_entry_get_available_nexthops(
      entry, msgbuf_get_connection_id(msgbuf), NULL);
  if (nexthops_get_curlen(nexthops) == 0) return nexthops;

#ifdef WITH_POLICY_STATS
  /*
   * Update statistics about loss rates. We only detect losses upon
   * retransmissions, and assume for the computation that the candidate set of
   * output faces is the same as previously (i.e. does not take into account
   * event such as face up/down, policy update, etc. Otherwise we would need to
   * know what was the previous choice !
   */
  if (is_retransmission)
    policy_stats_on_retransmission(mgr, &entry->policy_counters, nexthops);
#endif /* WITH_POLICY_STATS */

  /*
   * NOTE: We might want to call a forwarding strategy even with no nexthop to
   * take a fallback decision.
   */
  if (nexthops_get_curlen(nexthops) == 0) return nexthops;

#ifdef WITH_POLICY

  /*
   * Filter out nexthops with lowest strategy priority.
   * Initializing at 0 allows to disable nexthops with a negative priority
   */
  unsigned max_priority = 0;
  nexthops_enumerate(nexthops, i, nexthop, {
    int priority = nexthops->state[i].priority;
    if (priority > max_priority) max_priority = priority;
  });
  nexthops_enumerate(nexthops, i, nexthop, {
    int priority = nexthops->state[i].priority;
    nexthops_disable_if(nexthops, i, (priority < max_priority));
  });

  /*
   * If multipath is disabled, we don't offer much choice to the forwarding
   * strategy, but still go through it for accounting purposes.
   */
  hicn_policy_t policy = fib_entry_get_policy(entry);
  if ((policy.tags[POLICY_TAG_MULTIPATH].state == POLICY_STATE_PROHIBIT) ||
      (policy.tags[POLICY_TAG_MULTIPATH].state == POLICY_STATE_AVOID)) {
    DEBUG(
        "[fib_entry_get_nexthops_from_strategy] select single nexthops due to "
        "multipath policy");
    nexthops_select_first(nexthops);
  }

#endif /* WITH_POLICY */

  // DEBUG("[fib_entry_get_nexthops_from_strategy] calling lookup_nethops "
  // "on strategy (num=%d)", nexthops_get_len(nexthops));
  return strategy_lookup_nexthops(&entry->strategy, nexthops, msgbuf);
}

void fib_entry_on_data(fib_entry_t *entry, nexthops_t *data_nexthops,
                       const msgbuf_t *msgbuf, Ticks pitEntryCreation,
                       Ticks objReception) {
  assert(entry);
  assert(data_nexthops);
  assert(msgbuf);

#ifdef WITH_POLICY_STATS
  if (pitEntryCreation != 0) {  // if pitEntryCreation we no match in the pit
                                // was found
    const policy_stats_mgr_t *mgr =
        forwarder_get_policy_stats_mgr(entry->forwarder);
    Ticks rtt = objReception - pitEntryCreation;
    policy_stats_on_data(mgr, &entry->policy_stats, &entry->policy_counters,
                         data_nexthops, msgbuf, rtt);
  }
#endif /* WITH_POLICY_STATS */

  if (pitEntryCreation != 0 ||
      (fib_entry_strategy_type(entry) == STRATEGY_TYPE_BESTPATH)) {
    strategy_on_data(&entry->strategy, &entry->nexthops, data_nexthops, msgbuf,
                     pitEntryCreation, objReception);
  }
}

void fib_entry_on_timeout(fib_entry_t *entry,
                          const nexthops_t *timeout_nexthops) {
  assert(entry);
  assert(timeout_nexthops);

#ifdef WITH_POLICY_STATS
  const policy_stats_mgr_t *mgr =
      forwarder_get_policy_stats_mgr(entry->forwarder);
  policy_stats_on_timeout(mgr, &entry->policy_counters, timeout_nexthops);
#endif /* WITH_POLICY_STATS */

  strategy_on_timeout(&entry->strategy, &entry->nexthops, timeout_nexthops);
}

const hicn_prefix_t *fib_entry_get_prefix(const fib_entry_t *entry) {
  assert(entry);
  return &(entry->prefix);
}

/*
 * Return true if we have at least one local connection as next hop
 */
bool fib_entry_has_local_nexthop(const fib_entry_t *entry) {
  connection_table_t *table = forwarder_get_connection_table(entry->forwarder);

  nexthops_foreach(fib_entry_get_nexthops(entry), nexthop, {
    const connection_t *conn = connection_table_at(table, nexthop);
    /* Ignore non-local connections */
    if (!connection_is_local(conn)) continue;
    return true;
  });
  return false;
}

bool fib_entry_has_all_local_nexthops(const fib_entry_t *entry) {
  connection_table_t *table = forwarder_get_connection_table(entry->forwarder);

  nexthops_foreach(fib_entry_get_nexthops(entry), nexthop, {
    const connection_t *conn = connection_table_at(table, nexthop);
    /* Ignore non-local connections */
    if (!connection_is_local(conn)) return false;
  });
  return true;
}

#ifdef WITH_MAPME

void *fib_entry_get_user_data(const fib_entry_t *entry) {
  assert(entry);

  return entry->user_data;
}

void fib_entry_set_user_data(fib_entry_t *entry, const void *user_data,
                             void (*user_data_release)(void **)) {
  assert(entry);
  assert(user_data);
  assert(user_data_release);

  entry->user_data = (void *)user_data;
  entry->user_data_release = user_data_release;
}

#endif /* WITH_MAPME */
