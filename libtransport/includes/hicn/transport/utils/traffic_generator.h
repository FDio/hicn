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

#pragma once

#include <random>
#include <string>

namespace transport {

class TrafficGenerator {
 public:
  TrafficGenerator(uint32_t count);
  virtual ~TrafficGenerator() = default;
  bool hasFinished();
  uint32_t getSentCount();
  virtual std::pair<std::string, uint32_t> getPrefixAndSuffix();

  virtual std::string getPrefix() = 0;
  virtual uint32_t getSuffix() = 0;
  virtual void reset();

 protected:
  void onSuffixGenerated();

  uint32_t count_;
  uint32_t sent_;
};

/* Fixed prefix, incremental suffix */
class IncrSuffixTrafficGenerator : public TrafficGenerator {
 public:
  explicit IncrSuffixTrafficGenerator(std::string prefix, uint32_t suffix,
                                      uint32_t count);
  std::string getPrefix() override;
  uint32_t getSuffix() override;
  void reset() override;

 private:
  std::string prefix_;
  uint32_t suffix_;
  uint32_t initial_suffix_;
};

/* Random prefix, random suffix */
class RandomTrafficGenerator : public TrafficGenerator {
 public:
  static constexpr char NET_PREFIX[] = "2001:db8:1::/64";

  RandomTrafficGenerator(uint32_t count, std::string net_prefix = NET_PREFIX);
  std::string getPrefix() override;
  uint32_t getSuffix() override;

 private:
  std::string net_prefix_;
  std::default_random_engine rand_engine_;
  std::uniform_int_distribution<uint32_t> uniform_distribution_;
};

}  // namespace transport