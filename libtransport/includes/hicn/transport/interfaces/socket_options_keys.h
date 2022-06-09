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

#define SOCKET_OPTION_GET 0
#define SOCKET_OPTION_NOT_GET 1
#define SOCKET_OPTION_SET 2
#define SOCKET_OPTION_NOT_SET 3
#define SOCKET_OPTION_DEFAULT 12345

namespace transport {

namespace interface {

typedef enum {
  UNKNOWN = 0,
  BYTE_STREAM = 1,
  RTC_PROD = 2,
} ProductionProtocolAlgorithms;

typedef enum {
  RAAQM = 10,
  CBR = 11,
  RTC = 12,
} TransportProtocolAlgorithms;

typedef enum {
  RECOVERY_OFF = 20,
  RTX_ONLY = 21,
  FEC_ONLY = 22,
  DELAY_BASED = 23,
  LOW_RATE = 24,
  LOW_RATE_AND_BESTPATH = 25,
  LOW_RATE_AND_REPLICATION = 26,
  LOW_RATE_AND_ALL_FWD_STRATEGIES = 27,
  FEC_ONLY_LOW_RES_LOSSES = 28,
  DELAY_AND_BESTPATH = 29,
  DELAY_AND_REPLICATION = 30,
} RtcTransportRecoveryStrategies;

typedef enum {
  INPUT_BUFFER_SIZE = 101,
  OUTPUT_BUFFER_SIZE = 102,
  NETWORK_NAME = 103,
  NAME_SUFFIX = 104,
  MAX_INTEREST_RETX = 105,
  DATA_PACKET_SIZE = 106,
  INTEREST_LIFETIME = 107,
  CONTENT_OBJECT_EXPIRY_TIME = 108,
  MAX_SEGMENT_SIZE = 109,
  MIN_WINDOW_SIZE = 110,
  MAX_WINDOW_SIZE = 111,
  CURRENT_WINDOW_SIZE = 112,
  ASYNC_MODE = 113,
  PORTAL = 114,
  RUNNING = 115,
  APPLICATION_BUFFER = 116,
  HASH_ALGORITHM = 117,
  SIGNER = 118,
  VERIFIER = 119,
  MANIFEST_MAX_CAPACITY = 120,
  MANIFEST_FACTOR_RELEVANT = 121,
  MANIFEST_FACTOR_ALERT = 122,
  STATS_INTERVAL = 123,
  SUFFIX_STRATEGY = 124,
  PACKET_FORMAT = 125,
  FEC_TYPE = 126,
} GeneralTransportOptions;

typedef enum {
  SAMPLE_NUMBER = 201,
  GAMMA_VALUE = 202,
  BETA_VALUE = 203,
  DROP_FACTOR = 204,
  MINIMUM_DROP_PROBABILITY = 205,
  PATH_ID = 206,
  RTT_STATS = 207,
  PER_SESSION_CWINDOW_RESET = 208
} RaaqmTransportOptions;

typedef enum {
  RATE_ESTIMATION_ALPHA = 301,
  RATE_ESTIMATION_OBSERVER = 302,
  RATE_ESTIMATION_BATCH_PARAMETER = 303,
  RATE_ESTIMATION_CHOICE = 304,
} RateEstimationOptions;

typedef enum {
  INTEREST_OUTPUT = 401,
  INTEREST_RETRANSMISSION = 402,
  INTEREST_EXPIRED = 403,
  INTEREST_SATISFIED = 404,
  CONTENT_OBJECT_INPUT = 411,
  CONTENT_OBJECT_TO_VERIFY = 413,
  VERIFICATION_FAILED = 414,
  READ_CALLBACK = 415,
  STATS_SUMMARY = 416,
  FWD_STRATEGY_CHANGE = 417,
  REC_STRATEGY_CHANGE = 418,
} ConsumerCallbacksOptions;

typedef enum {
  INTEREST_INPUT = 501,
  INTEREST_DROP = 502,
  INTEREST_PASS = 503,
  CACHE_HIT = 506,
  CACHE_MISS = 508,
  NEW_CONTENT_OBJECT = 509,
  CONTENT_OBJECT_READY = 510,
  CONTENT_OBJECT_OUTPUT = 511,
  CONTENT_PRODUCED = 512,
  CONTENT_OBJECT_TO_SIGN = 513,
  PRODUCER_CALLBACK = 514,
} ProducerCallbacksOptions;

typedef enum { OUTPUT_INTERFACE = 601 } DataLinkOptions;

typedef enum {
  VIRTUAL_DOWNLOAD = 701,
  USE_CFG_FILE = 702,
  STATISTICS
} OtherOptions;

typedef enum {
  SHA_256 = 801,
  RSA_256 = 802,
} SignatureType;

typedef enum {
  RECOVERY_STRATEGY = 901,
  AGGREGATED_DATA = 902,
  CONTENT_SHARING_MODE = 903,
  AGGREGATED_INTERESTS = 904,
} RtcTransportOptions;

}  // namespace interface

}  // end namespace transport
