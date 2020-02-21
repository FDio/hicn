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

#include <core/manifest_format.h>

namespace utils {

using transport::core::NextSegmentCalculationStrategy;

class SuffixStrategy {
 public:
  static constexpr uint32_t INVALID_SUFFIX =
      std::numeric_limits<uint32_t>::max();

  SuffixStrategy(NextSegmentCalculationStrategy strategy)
      : suffix_stragegy_(strategy),
        total_count_(0),
        final_suffix_(INVALID_SUFFIX) {}

  virtual ~SuffixStrategy() = default;

  virtual uint32_t getNextSuffix() = 0;

  virtual uint32_t getFinalSuffix() { return final_suffix_; }

  virtual void setFinalSuffix(std::uint32_t final_suffix) {
    if (final_suffix != INVALID_SUFFIX) {
      final_suffix_ = final_suffix;
    }
  }

  virtual uint32_t getNextManifestSuffix() = 0;

  virtual uint32_t getNextContentSuffix() = 0;

  virtual void reset(uint32_t offset = 0) = 0;

  virtual uint32_t getManifestCapacity() = 0;

  virtual void setManifestCapacity(uint32_t capacity) = 0;

  virtual uint32_t getTotalCount() { return total_count_; };

  NextSegmentCalculationStrategy getSuffixStrategy() {
    return suffix_stragegy_;
  }

 protected:
  inline void incrementTotalCount() { total_count_++; };

 protected:
  NextSegmentCalculationStrategy suffix_stragegy_;
  std::uint32_t total_count_;
  std::uint32_t final_suffix_;
};

class IncrementalSuffixStrategy : public SuffixStrategy {
 public:
  IncrementalSuffixStrategy(std::uint32_t start_offset)
      : SuffixStrategy(NextSegmentCalculationStrategy::INCREMENTAL),
        next_suffix_(start_offset) {}

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextSuffix() override {
    incrementTotalCount();
    return next_suffix_++;
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextContentSuffix() override {
    return getNextSuffix();
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextManifestSuffix() override {
    return getNextSuffix();
  }

  uint32_t getManifestCapacity() override {
    throw errors::RuntimeException(
        "No manifest capacity in IncrementalSuffixStrategy.");
  }

  void setManifestCapacity(uint32_t capacity) override {
    throw errors::RuntimeException(
        "No manifest capacity in IncrementalSuffixStrategy.");
  }

  void reset(std::uint32_t offset = 0) override { next_suffix_ = offset; }

 protected:
  std::uint32_t next_suffix_;
};

class CapacityBasedSuffixStrategy : public SuffixStrategy {
 public:
  CapacityBasedSuffixStrategy(std::uint32_t start_offset,
                              std::uint32_t manifest_capacity)
      : SuffixStrategy(NextSegmentCalculationStrategy::INCREMENTAL),
        next_suffix_(start_offset),
        segments_in_manifest_(manifest_capacity),
        current_manifest_iteration_(0) {}

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextSuffix() override {
    incrementTotalCount();
    return next_suffix_++;
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextContentSuffix() override {
    incrementTotalCount();
    return next_suffix_ % segments_in_manifest_ == 0 ? next_suffix_++
                                                     : ++next_suffix_;
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextManifestSuffix() override {
    incrementTotalCount();
    return (current_manifest_iteration_++) * (segments_in_manifest_ + 1);
  }

  TRANSPORT_ALWAYS_INLINE uint32_t getManifestCapacity() override {
    return segments_in_manifest_;
  }

  TRANSPORT_ALWAYS_INLINE void setManifestCapacity(uint32_t capacity) override {
    segments_in_manifest_ = capacity;
  }

  void reset(std::uint32_t offset = 0) override { next_suffix_ = offset; }

 protected:
  std::uint32_t next_suffix_;
  std::uint32_t segments_in_manifest_;
  std::uint32_t current_manifest_iteration_;
};

class SuffixStrategyFactory {
 public:
  static std::unique_ptr<SuffixStrategy> getSuffixStrategy(
      NextSegmentCalculationStrategy strategy, uint32_t start_offset,
      uint32_t manifest_capacity = 0) {
    switch (strategy) {
      case NextSegmentCalculationStrategy::INCREMENTAL:
        return std::make_unique<IncrementalSuffixStrategy>(start_offset);
      case NextSegmentCalculationStrategy::MANIFEST_CAPACITY_BASED:
        return std::make_unique<CapacityBasedSuffixStrategy>(start_offset,
                                                             manifest_capacity);
      default:
        throw errors::RuntimeException(
            "No valid NextSegmentCalculationStrategy specified.");
    }
  }
};

}  // namespace utils
