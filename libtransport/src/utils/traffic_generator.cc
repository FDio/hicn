/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <hicn/transport/core/prefix.h>
#include <hicn/transport/utils/traffic_generator.h>

#include <iostream>
#include <random>

namespace transport {

/* TrafficGenerator */

TrafficGenerator::TrafficGenerator(uint32_t count) : count_(count), sent_(0) {}

bool TrafficGenerator::hasFinished() { return sent_ >= count_; }

uint32_t TrafficGenerator::getSentCount() { return sent_; }

std::pair<std::string, uint32_t> TrafficGenerator::getPrefixAndSuffix() {
  return std::make_pair(getPrefix(), getSuffix());
}

void TrafficGenerator::reset() { sent_ = 0; };

void TrafficGenerator::onSuffixGenerated() {
  if (hasFinished()) throw std::runtime_error("Too many pings");
  sent_++;
};

/* IncrSuffixTrafficGenerator */

IncrSuffixTrafficGenerator::IncrSuffixTrafficGenerator(std::string prefix,
                                                       uint32_t suffix,
                                                       uint32_t count)
    : TrafficGenerator(count),
      prefix_(prefix),
      suffix_(suffix),
      initial_suffix_(suffix) {}

std::string IncrSuffixTrafficGenerator::getPrefix() { return prefix_; }

uint32_t IncrSuffixTrafficGenerator::getSuffix() {
  TrafficGenerator::onSuffixGenerated();
  return suffix_++;
}

void IncrSuffixTrafficGenerator::reset() {
  TrafficGenerator::reset();
  suffix_ = initial_suffix_;
};

/* RandomTrafficGenerator */

RandomTrafficGenerator::RandomTrafficGenerator(uint32_t count,
                                               std::string net_prefix)
    : TrafficGenerator(count), net_prefix_(net_prefix) {}

std::string RandomTrafficGenerator::getPrefix() {
  // Generate random prefix
  core::Prefix prefix(net_prefix_);
  core::Name name = prefix.makeRandomName();
  return name.getPrefix();
}

uint32_t RandomTrafficGenerator::getSuffix() {
  TrafficGenerator::onSuffixGenerated();

  // Generate random suffix
  std::default_random_engine eng((std::random_device())());
  std::uniform_int_distribution<uint32_t> idis(
      0, std::numeric_limits<uint32_t>::max());
  return idis(eng);
}

}  // namespace transport