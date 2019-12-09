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
 * Forward on the path with lowest latency
 */

#ifndef HICNLIGHT_STRATEGY_LOW_LATENCY_H
#define HICNLIGHT_STRATEGY_LOW_LATENCY_H

#define MAX_FWD_STRATEGY_RELATED_PREFIXES 10

typedef struct {
  //Name ** related_prefixes;
  Name *related_prefixes[MAX_FWD_STRATEGY_RELATED_PREFIXES];
  unsigned related_prefixes_len;
} strategy_low_latency_options_t;

#if 0

/*
 * We have global state in addition to state associated for each next hop :
 */
typedef struct {
  bool in_use;
  bool is_allowed; // XXX TODO the policy may not allow the use of this face
//  unsigned face_id;
  unsigned sent_packets;
  /* switch metrics */
  unsigned last_try_to_switch_round;
  unsigned try_to_switch_counter;
  /* probes counters */
  unsigned recevied_probes;
  unsigned rounds_without_probes;
  unsigned sent_probes;
  unsigned lost_probes;
  unsigned non_lossy_rounds;
  /* Averages */
  double avg_rtt;
  double avg_rtt_in_use;
  double avg_queue;
  double avg_loss_rate;
} strategy_low_latency_nexthop_state_t;

typedef struct {
  // hash map from connectionId to StrategyNexthopStateLL
  //PARCHashMap *strategy_state;
  // XXX This is now store in each nexthop state

  /*
   * Hhash map from sequence number to ticks (sent time)
   *
   * TODO improvement: the tick and face id could be stored in the probe and
   * repeated in the reply to avoid state to be maintained.
   *
   * Also, in case we have few probes, linear scan might be more effective
   */
  PARCHashMap *pending_probes_ticks;

  /* hash map from sequence number to face id */
  PARCHashMap *pending_probes_faces;

  const Forwarder * forwarder;
  PARCEventTimer *sendProbes;
  PARCEventTimer *computeBestFace;
  uint8_t * probe;
  hicn_name_t * name;
  StrategyNexthopStateLL * bestFaces[2];
  unsigned round;
  unsigned rounds_in_multipath;
  unsigned rounds_with_error;
  unsigned rounds_avoiding_multipath;
  bool use2paths;
  bool avoid_multipath;
} strategy_low_latency_state_t;

#endif


#endif /* HICNLIGHT_STRATEGY_LOW_LATENCY_H */
