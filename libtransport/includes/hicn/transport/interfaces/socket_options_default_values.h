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

#include <hicn/base.h>
#include <chrono>
#include <cstdint>

namespace transport {

namespace interface {

namespace default_values {

static constexpr uint32_t interest_lifetime = 1001;  // milliseconds
static constexpr uint32_t never_expire_time = HICN_MAX_LIFETIME;
static constexpr uint32_t content_object_expiry_time =
    never_expire_time;  // milliseconds -> 50 seconds
static constexpr uint32_t content_object_packet_size =
    1500;  // The ethernet MTU
static constexpr uint32_t producer_socket_output_buffer_size =
    150000;  // Content Object
static constexpr uint32_t log_2_default_buffer_size = 12;
static constexpr uint32_t signature_size = 260;           // bytes
static constexpr uint32_t key_locator_size = 60;          // bytes
static constexpr uint32_t limit_guard = 80;               // bytes
static constexpr uint32_t digest_size = 34;               // bytes
static constexpr uint32_t max_out_of_order_segments = 3;  // content object

// RAAQM
static constexpr int sample_number = 30;
static constexpr double gamma_value = 1;
static constexpr double beta_value = 0.8;
static constexpr double drop_factor = 0.2;
static constexpr double minimum_drop_probability = 0.00001;
static constexpr int path_id = 0;
static constexpr double rate_alpha = 0.8;

// Rate estimation
static constexpr uint32_t batch = 50;
static constexpr uint32_t kv = 20;
static constexpr double alpha = 0.8;
static constexpr uint32_t rate_choice = 0;

// maximum allowed values
static constexpr uint32_t transport_protocol_min_retransmissions = 0;
static constexpr uint32_t transport_protocol_max_retransmissions = 128;
static constexpr uint32_t max_content_object_size = 8096;
static constexpr uint32_t min_window_size = 1;        // Interests
static constexpr uint32_t max_window_size = 256 * 2;  // Interests

}  // namespace default_values

}  // namespace interface

}  // end namespace transport
