/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
const uint32_t PRODUCER_BUFFER_MS = 300;  // ms

// interest scheduler
// const uint32_t MAX_INTERESTS_IN_BATCH = 5;
// const uint32_t WAIT_BETWEEN_INTEREST_BATCHES = 1000;  // usec
const uint32_t MAX_INTERESTS_IN_BATCH = 5;    // number of seq numbers per
                                              // aggregated interest packet
                                              // considering the name itself
const uint32_t WAIT_FOR_INTEREST_BATCH = 20;  // msec. timer that we wait to try
                                              // to aggregate interest in the
                                              // same packet
const uint32_t MAX_PACING_BATCH = 5;  // number of interest that we can send
                                      // inside the loop before they get dropped
                                      // by the kernel.
const uint32_t PACING_WAIT = 1000;  // usec to wait betwing two pacing batch. As
                                    // for MAX_PACING_BATCH this value was
                                    // computed during tests
const uint32_t MAX_RTX_IN_BATCH = 10;  // max rtx to send in loop

// packet const
const uint32_t RTC_INTEREST_LIFETIME = 4000;

// probes sequence range
const uint32_t MIN_PROBE_SEQ = 0xefffffff;
const uint32_t MIN_INIT_PROBE_SEQ = MIN_PROBE_SEQ;
const uint32_t MAX_INIT_PROBE_SEQ = 0xf7ffffff - 1;
const uint32_t MIN_RTT_PROBE_SEQ = MAX_INIT_PROBE_SEQ + 1;
const uint32_t MAX_RTT_PROBE_SEQ = 0xffffffff - 1;
// RTT_PROBE_INTERVAL will be used during the section while
// INIT_RTT_PROBE_INTERVAL is used at the beginning to
// quickily estimate the RTT
const uint32_t RTT_PROBE_INTERVAL = 200000;    // us
const uint32_t INIT_RTT_PROBE_INTERVAL = 500;  // us
const uint32_t INIT_RTT_PROBES = 40;           // number of probes to init RTT
// if the produdcer is not yet started we need to probe multple times
// to get an answer. we wait 100ms between each try
const uint32_t INIT_RTT_PROBE_RESTART = 100;  // ms
// once we get the first probe we wait at most 60ms for the others
const uint32_t INIT_RTT_PROBE_WAIT =
    ((INIT_RTT_PROBES * INIT_RTT_PROBE_INTERVAL) / 1000) * 2;  // ms
// we reuires at least 5 probes to be recevied
const uint32_t INIT_RTT_MIN_PROBES_TO_RECV = 5;  // ms
const uint32_t MAX_PENDING_PROBES = 10;

// congestion
const double MAX_QUEUING_DELAY = 50.0;  // ms

// data from cache
const double MAX_DATA_FROM_CACHE = 0.10;  // 10%

// window const
const uint32_t INITIAL_WIN = 5;                    // pkts
const uint32_t INITIAL_WIN_MAX = 1000000;          // pkts
const uint32_t WIN_MIN = 5;                        // pkts
const uint32_t WIN_MIN_WITH_AGGREGARED_DATA = 10;  // pkts
const double CATCH_UP_WIN_INCREMENT = 1.2;
// used in rate control
const double WIN_DECREASE_FACTOR = 0.5;
const double WIN_INCREASE_FACTOR = 1.5;
const uint32_t MIN_PROD_RATE_SHARING_MODE = 125000;  // 1Mbps in bytes

// round in congestion
const double ROUNDS_BEFORE_TAKE_ACTION = 5;

// used in state
const uint8_t ROUNDS_IN_SYNC_BEFORE_SWITCH = 3;
const double PRODUCTION_RATE_FRACTION = 0.8;

const uint32_t INIT_PACKET_SIZE = 1200;

const double MOVING_AVG_ALPHA = 0.8;

const double MILLI_IN_A_SEC = 1000.0;
const double MICRO_IN_A_SEC = 1000000.0;
const uint32_t ROUNDS_PER_SEC = (uint32_t)(MILLI_IN_A_SEC / ROUND_LEN);
const uint32_t ROUNDS_PER_MIN = (uint32_t)ROUNDS_PER_SEC * 60;

const uint32_t MAX_ROUND_WHIOUT_PACKETS =
    (20 * MILLI_IN_A_SEC) / ROUND_LEN;  // 20 sec in rounds;

// used in ldr
const uint32_t RTC_MAX_RTX = 100;
const uint32_t RTC_MAX_AGE = 60000;  // in ms
const uint64_t MAX_TIMER_RTX = ~0;
const uint32_t SENTINEL_TIMER_INTERVAL = 100;  // ms
const uint32_t MAX_RTX_WITH_SENTINEL = 10;     // packets
const double CATCH_UP_RTT_INCREMENT = 1.2;
const double MAX_RESIDUAL_LOSS_RATE = 2.0;  // %
const uint32_t WAIT_BEFORE_FEC_UPDATE = ROUNDS_PER_SEC * 5;
const uint32_t MAX_RTT_BEFORE_FEC = 60;  // ms

// used by producer
const uint32_t PRODUCER_STATS_INTERVAL = 200;  // ms
const uint32_t MIN_PRODUCTION_RATE = 25;       // pps, equal to min window *
                                               // rounds in a second
const uint32_t FEC_PACING_TIME = 5;            // ms

// aggregated data consts
const uint16_t MAX_RTC_PAYLOAD_SIZE = 1200;   // bytes
const uint16_t MAX_AGGREGATED_PACKETS = 5;    // pkt
const uint32_t AGGREGATED_PACKETS_TIMER = 2;  // ms

// alert thresholds
const uint32_t MAX_RTT = 200;             // ms
const double MAX_RESIDUAL_LOSSES = 0.05;  // %

const uint8_t FEC_MATRIX[64][10] = {
    {1, 2, 2, 2, 3, 3, 4, 5, 5, 6},  // k = 1
    {1, 2, 3, 3, 4, 5, 5, 6, 7, 9},
    {2, 2, 3, 4, 5, 6, 7, 8, 9, 11},
    {2, 3, 4, 5, 5, 7, 8, 9, 11, 13},
    {2, 3, 4, 5, 6, 7, 9, 10, 12, 14},  // k = 5
    {2, 3, 4, 6, 7, 8, 10, 12, 14, 16},
    {2, 4, 5, 6, 8, 9, 11, 13, 15, 18},
    {3, 4, 5, 7, 8, 10, 12, 14, 16, 19},
    {3, 4, 6, 7, 9, 11, 13, 15, 18, 21},
    {3, 4, 6, 8, 9, 11, 14, 16, 19, 23},  // k = 10
    {3, 5, 6, 8, 10, 12, 14, 17, 20, 24},
    {3, 5, 7, 8, 10, 13, 15, 18, 21, 26},
    {3, 5, 7, 9, 11, 13, 16, 19, 23, 27},
    {3, 5, 7, 9, 12, 14, 17, 20, 24, 28},
    {4, 6, 8, 10, 12, 15, 18, 21, 25, 30},  // k = 15
    {4, 6, 8, 10, 13, 15, 19, 22, 26, 31},
    {4, 6, 8, 11, 13, 16, 19, 23, 27, 33},
    {4, 6, 9, 11, 14, 17, 20, 24, 29, 34},
    {4, 6, 9, 11, 14, 17, 21, 25, 30, 35},
    {4, 7, 9, 12, 15, 18, 22, 26, 31, 37},  // k = 20
    {4, 7, 9, 12, 15, 19, 22, 27, 32, 38},
    {4, 7, 10, 13, 16, 19, 23, 28, 33, 40},
    {5, 7, 10, 13, 16, 20, 24, 29, 34, 41},
    {5, 7, 10, 13, 17, 20, 25, 30, 35, 42},
    {5, 8, 11, 14, 17, 21, 26, 31, 37, 44},  // k = 25
    {5, 8, 11, 14, 18, 22, 26, 31, 38, 45},
    {5, 8, 11, 15, 18, 22, 27, 32, 39, 46},
    {5, 8, 11, 15, 19, 23, 28, 33, 40, 48},
    {5, 8, 12, 15, 19, 24, 28, 34, 41, 49},
    {5, 9, 12, 16, 20, 24, 29, 35, 42, 50},  // k = 30
    {5, 9, 12, 16, 20, 25, 30, 36, 43, 51},
    {5, 9, 13, 16, 21, 25, 31, 37, 44, 53},
    {6, 9, 13, 17, 21, 26, 31, 38, 45, 54},
    {6, 9, 13, 17, 22, 26, 32, 39, 46, 55},
    {6, 10, 13, 17, 22, 27, 33, 40, 47, 57},  // k = 35
    {6, 10, 14, 18, 22, 28, 34, 40, 48, 58},
    {6, 10, 14, 18, 23, 28, 34, 41, 49, 59},
    {6, 10, 14, 19, 23, 29, 35, 42, 50, 60},
    {6, 10, 14, 19, 24, 29, 36, 43, 52, 62},
    {6, 10, 15, 19, 24, 30, 36, 44, 53, 63},  // k = 40
    {6, 11, 15, 20, 25, 31, 37, 45, 54, 64},
    {6, 11, 15, 20, 25, 31, 38, 46, 55, 65},
    {7, 11, 15, 20, 26, 32, 39, 46, 56, 67},
    {7, 11, 16, 21, 26, 32, 39, 47, 57, 68},
    {7, 11, 16, 21, 27, 33, 40, 48, 58, 69},  // k = 45
    {7, 11, 16, 21, 27, 33, 41, 49, 59, 70},
    {7, 12, 16, 22, 27, 34, 41, 50, 60, 72},
    {7, 12, 17, 22, 28, 34, 42, 51, 61, 73},
    {7, 12, 17, 22, 28, 35, 43, 52, 62, 74},
    {7, 12, 17, 23, 29, 36, 43, 52, 63, 75},  // k = 50
    {7, 12, 17, 23, 29, 36, 44, 53, 64, 77},
    {7, 12, 18, 23, 30, 37, 45, 54, 65, 78},
    {7, 13, 18, 24, 30, 37, 45, 55, 66, 79},
    {8, 13, 18, 24, 31, 38, 46, 56, 67, 80},
    {8, 13, 18, 24, 31, 38, 47, 57, 68, 82},  // k = 55
    {8, 13, 19, 25, 31, 39, 47, 57, 69, 83},
    {8, 13, 19, 25, 32, 39, 48, 58, 70, 84},
    {8, 13, 19, 25, 32, 40, 49, 59, 71, 85},
    {8, 14, 19, 26, 33, 41, 50, 60, 72, 86},
    {8, 14, 20, 26, 33, 41, 50, 61, 73, 88},  // k = 60
    {8, 14, 20, 26, 34, 42, 51, 61, 74, 89},
    {8, 14, 20, 27, 34, 42, 52, 62, 75, 90},
    {8, 14, 20, 27, 34, 43, 52, 63, 76, 91},
    {8, 14, 21, 27, 35, 43, 53, 64, 77, 92},  // k = 64
};

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
