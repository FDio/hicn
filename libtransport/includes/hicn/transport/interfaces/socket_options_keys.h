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

#pragma once

#define SOCKET_OPTION_GET 0
#define SOCKET_OPTION_NOT_GET 1
#define SOCKET_OPTION_SET 2
#define SOCKET_OPTION_NOT_SET 3
#define SOCKET_OPTION_DEFAULT 12345

namespace transport {

namespace interface {

typedef enum {
  RAAQM = 0,
  CBR = 1,
  RTC = 2,
} TransportProtocolAlgorithms;

typedef enum {
  INPUT_BUFFER_SIZE = 101,
  OUTPUT_BUFFER_SIZE = 102,
  NETWORK_NAME = 103,
  NAME_SUFFIX = 104,
  MAX_INTEREST_RETX = 105,
  DATA_PACKET_SIZE = 106,
  INTEREST_LIFETIME = 107,
  CONTENT_OBJECT_EXPIRY_TIME = 108,
  KEY_CONTENT = 110,
  MIN_WINDOW_SIZE = 111,
  MAX_WINDOW_SIZE = 112,
  CURRENT_WINDOW_SIZE = 113,
  ASYNC_MODE = 114,
  MAKE_MANIFEST = 115,
  PORTAL = 116,
  RUNNING = 117,
  APPLICATION_BUFFER = 118,
  HASH_ALGORITHM = 119,
  CRYPTO_SUITE = 120,
  SIGNER = 121,
  VERIFIER = 122,
  CERTIFICATE = 123,
  VERIFY_SIGNATURE = 124,
  STATS_INTERVAL = 125,
} GeneralTransportOptions;

typedef enum {
  SAMPLE_NUMBER = 201,
  GAMMA_VALUE = 202,
  BETA_VALUE = 203,
  DROP_FACTOR = 204,
  MINIMUM_DROP_PROBABILITY = 205,
  PATH_ID = 206,
  RTT_STATS = 207,
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
  STATS_SUMMARY = 416
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

}  // namespace interface

}  // end namespace transport
