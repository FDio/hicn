/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef transport_algorithm_h
#define transport_algorithm_h

#include <hicn/header.h>
#include <hicn/transport/interfaces/socket_options_keys.h>
#include <stddef.h>
#include <stdint.h>

/**
 * TransportAlgorithm: class containing the protocol machinery
 */
#ifdef __cplusplus

#include <hicn/transport/core/content_object.h>

class TransportAlgorithm {
 public:
  virtual ~TransportAlgorithm() = default;
  virtual void reset() = 0;
  virtual uint32_t onContentObject(uint32_t suffix, uint32_t path_label) = 0;
  virtual uint32_t onInterestTimeout(uint32_t suffix) = 0;
  virtual void onInterestSent(uint32_t suffix) = 0;
  virtual void sessionEnd() = 0;
};

using transport::interface::TransportProtocolAlgorithms;

#else
typedef void *TransportAlgorithm;
#endif

typedef void *(allocator_t)(size_t size);
typedef void *(deallocator_t)(void *ptr);

extern "C" void transportAlgorithm_Init(allocator_t *allocator,
                                        deallocator_t *deallocator);

extern "C" TransportAlgorithm *transportAlgorithm_CreateRaaqm(
    double drop_factor, double minimum_drop_probability, double gamma,
    double beta, uint32_t sample_number, uint32_t interest_lifetime,
    double beta_wifi, double drop_wifi, double beta_lte, double drop_lte,
    unsigned int wifi_delay, unsigned int lte_delay, double max_window,
    double min_window);

extern "C" void transportAlgorithm_Destroy(TransportAlgorithm *algorithm);

extern "C" uint32_t transportAlgorithm_OnContentObject(
    TransportAlgorithm *algorithm, uint32_t suffix, uint32_t path_label);

extern "C" uint32_t transportAlgorithm_OnInterestTimeout(
    TransportAlgorithm *algorithm, uint32_t suffix);

#endif /* transport_algorithm_h */