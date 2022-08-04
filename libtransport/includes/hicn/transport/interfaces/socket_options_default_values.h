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

#pragma once

#include <hicn/transport/portability/portability.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/base.h>
};

#include <chrono>
#include <cstdint>

namespace transport {

namespace interface {

namespace default_values {

// Packet format
// #define NEW_PACKET_FORMAT
static constexpr hicn_packet_format_t packet_format =
#ifdef NEW_PACKET_FORMAT
    HICN_PACKET_FORMAT_NEW;
#else
    HICN_PACKET_FORMAT_IPV6_TCP;
#endif

// Parameters
static const uint32_t interest_lifetime = 1001;  // milliseconds
static const uint32_t never_expire_time = HICN_MAX_LIFETIME;
static const uint32_t content_object_expiry_time =
    never_expire_time;  // milliseconds -> 50 seconds
static const uint32_t content_object_packet_size = 1500;  // The ethernet MTU
static const uint32_t producer_socket_output_buffer_size =
    150000;  // Content Object
static constexpr uint32_t log_2_default_buffer_size = 12;
static constexpr uint32_t signature_size = 260;           // bytes
static constexpr uint32_t key_locator_size = 60;          // bytes
static constexpr uint32_t limit_guard = 80;               // bytes
static constexpr uint32_t digest_size = 34;               // bytes
static constexpr uint32_t max_out_of_order_segments = 3;  // content object
static constexpr uint32_t manifest_max_capacity = 30;
static constexpr uint32_t manifest_factor_relevant = 100;
static constexpr uint32_t manifest_factor_alert = 20;

// RAAQM
static const int sample_number = 30;
static const double gamma_value = 1;
static const double beta_value = 0.8;
static const double drop_factor = 0.2;
static const double minimum_drop_probability = 0.00001;
static const int path_id = 0;
static const double rate_alpha = 0.8;

// Rate estimation
static const uint32_t batch = 50;
static const uint32_t kv = 20;
static const double alpha = 0.8;
static const uint32_t rate_choice = 0;

// maximum allowed values
static const uint32_t transport_protocol_min_retransmissions = 0;
static const uint32_t transport_protocol_max_retransmissions = 128;
static const uint32_t max_content_object_size = 8096;
static const uint32_t min_window_size = 1;        // Interests
static const uint32_t max_window_size = 256 * 2;  // Interests

}  // namespace default_values

}  // namespace interface

}  // end namespace transport
