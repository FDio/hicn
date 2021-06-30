/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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

#pragma once

#include <protocols/rtc/rtc_packet.h>
#include <stdint.h>

namespace transport {

namespace protocol {

namespace rtc {

// used in rtc
// protocol consts
const uint32_t ROUND_LEN = 200;
// ms interval of time on which
// we take decisions / measurements
const double INTEREST_LIFETIME_REDUCTION_FACTOR = 0.8;
// how big (in ms) should be the buffer at the producer.
// increasing this number we increase the time that an
// interest will wait for the data packet to be produced
// at the producer socket
const uint32_t PRODUCER_BUFFER_MS = 200;  // ms

// interest scheduler
//const uint32_t MAX_INTERESTS_IN_BATCH = 5;
//const uint32_t WAIT_BETWEEN_INTEREST_BATCHES = 1000;  // usec
const uint32_t MAX_INTERESTS_IN_BATCH = 5; // number of seq numbers per
                                           // aggregated interest packet
                                           // considering the name itself
const uint32_t WAIT_FOR_INTEREST_BATCH = 20;  // msec. timer that we wait to try
                                              // to aggregate interest in the
                                              // same packet
const uint32_t MAX_PACING_BATCH = 5;
                                // number of interest that we can send inside
                                // the loop before they get dropped by the
                                // kernel.
const uint32_t PACING_WAIT = 1000; // usec to wait betwing two pacing batch. As
                                   // for MAX_PACING_BATCH this value was
                                   // computed during tests
const uint32_t MAX_RTX_IN_BATCH = 10; // max rtx to send in loop

// packet const
const uint32_t HICN_HEADER_SIZE = 40 + 20;  //  IPv6 + TCP bytes
const uint32_t RTC_INTEREST_LIFETIME = 2000;

// probes sequence range
const uint32_t MIN_PROBE_SEQ = 0xefffffff;
const uint32_t MIN_RTT_PROBE_SEQ = MIN_PROBE_SEQ;
const uint32_t MAX_RTT_PROBE_SEQ = 0xffffffff - 1;
// RTT_PROBE_INTERVAL will be used during the section while
// INIT_RTT_PROBE_INTERVAL is used at the beginning to
// quickily estimate the RTT
const uint32_t RTT_PROBE_INTERVAL = 200000;  // us
const uint32_t INIT_RTT_PROBE_INTERVAL = 500; // us
const uint32_t INIT_RTT_PROBES = 40; // number of probes to init RTT
// if the produdcer is not yet started we need to probe multple times
// to get an answer. we wait 100ms between each try
const uint32_t INIT_RTT_PROBE_RESTART = 100; // ms
// once we get the first probe we wait at most 60ms for the others
const uint32_t INIT_RTT_PROBE_WAIT = 30; // ms
// we reuires at least 5 probes to be recevied
const uint32_t INIT_RTT_MIN_PROBES_TO_RECV = 5; //ms
const uint32_t MAX_PENDING_PROBES = 10;


// congestion
const double MAX_QUEUING_DELAY = 100.0;  // ms

// data from cache
const double MAX_DATA_FROM_CACHE = 0.25;  // 25%

// window const
const uint32_t INITIAL_WIN = 5;            // pkts
const uint32_t INITIAL_WIN_MAX = 1000000;  // pkts
const uint32_t WIN_MIN = 5;                // pkts
const double CATCH_UP_WIN_INCREMENT = 1.2;
// used in rate control
const double WIN_DECREASE_FACTOR = 0.5;
const double WIN_INCREASE_FACTOR = 1.5;

// round in congestion
const double ROUNDS_BEFORE_TAKE_ACTION = 5;

// used in state
const uint8_t ROUNDS_IN_SYNC_BEFORE_SWITCH = 3;
const double PRODUCTION_RATE_FRACTION = 0.8;

const uint32_t INIT_PACKET_SIZE = 1200;

const double MOVING_AVG_ALPHA = 0.8;

const double MILLI_IN_A_SEC = 1000.0;
const double MICRO_IN_A_SEC = 1000000.0;

const double MAX_CACHED_PACKETS = 262144;  // 2^18
                                           // about 50 sec of traffic at 50Mbps
                                           // with 1200 bytes packets

const uint32_t MAX_ROUND_WHIOUT_PACKETS =
    (20 * MILLI_IN_A_SEC) / ROUND_LEN;  // 20 sec in rounds;

// used in ldr
const uint32_t RTC_MAX_RTX = 100;
const uint32_t RTC_MAX_AGE = 60000;  // in ms
const uint64_t MAX_TIMER_RTX = ~0;
const uint32_t SENTINEL_TIMER_INTERVAL = 100;  // ms
const uint32_t MAX_RTX_WITH_SENTINEL = 10;     // packets
const double CATCH_UP_RTT_INCREMENT = 1.2;

// used by producer
const uint32_t PRODUCER_STATS_INTERVAL = 200;  // ms
const uint32_t MIN_PRODUCTION_RATE = 10;       // pps
                                               // min prod rate
                                               // set running several test

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
