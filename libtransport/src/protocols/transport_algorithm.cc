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

#include <hicn/transport/protocols/transport_algorithm.h>
#include <hicn/transport/utils/log.h>
#include <protocols/raaqm_transport_algorithm.h>

#include <stdexcept>

namespace {
allocator_t *algorithm_allocator = nullptr;
deallocator_t *algorithm_deallocator = nullptr;

void *custom_allocate(size_t size) {
  void *ret;
  if (algorithm_allocator) {
    ret = algorithm_allocator(size);
  } else {
    ret = new uint8_t[size];
  }

  return ret;
}

void custom_deallocate(void *p) {
  if (algorithm_deallocator) {
    algorithm_deallocator(p);
  } else {
    delete[](char *)(p);
  }
}

}  // namespace

extern "C" void transportAlgorithm_Init(allocator_t *allocator,
                                        deallocator_t *deallocator) {
  algorithm_allocator = allocator;
  algorithm_deallocator = deallocator;
}

extern "C" void transportAlgorithm_Destroy(TransportAlgorithm *algorithm) {
  custom_deallocate(algorithm);
}

extern "C" TransportAlgorithm *transportAlgorithm_CreateRaaqm(
    double drop_factor, double minimum_drop_probability, double gamma,
    double beta, uint32_t sample_number, uint32_t interest_lifetime,
    double beta_wifi, double drop_wifi, double beta_lte, double drop_lte,
    unsigned int wifi_delay, unsigned int lte_delay, double max_window,
    double min_window) {
  TransportAlgorithm *ret = nullptr;
  ret = new (
      custom_allocate(sizeof(transport::protocol::RaaqmTransportAlgorithm)))
      transport::protocol::RaaqmTransportAlgorithm(
          nullptr, nullptr, drop_factor, minimum_drop_probability, gamma, beta,
          sample_number, interest_lifetime, beta_wifi, drop_wifi, beta_lte,
          drop_lte, wifi_delay, lte_delay, max_window, min_window);

  return ret;
}

extern "C" uint32_t transportAlgorithm_OnContentObject(
    TransportAlgorithm *algorithm, uint32_t suffix, uint32_t path_label) {
  return algorithm->onContentObject(suffix, path_label);
}

extern "C" uint32_t transportAlgorithm_OnInterestTimeout(
    TransportAlgorithm *algorithm, uint32_t suffix) {
  return algorithm->onInterestTimeout(suffix);
}