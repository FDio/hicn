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

#include <hicn/transport/core/name.h>
#include <hicn/transport/errors/runtime_exception.h>

namespace utils {

/**
 * INCREMENTAL: Manifests will be received inline with the data with no specific
 * assumption regarding the manifest capacity. Consumers can send interests
 * using a +1 heuristic.
 *
 * MANIFEST_CAPACITY_BASED: manifests with capacity N have a suffix multiple of
 * N+1: 0, N+1, 2(N+1) etc. Contents have a suffix incremented by 1 except when
 * it conflicts with a manifest: 1, 2, ..., N, N+2, N+3, ..., 2N+1, 2N+3
 */
enum class NextSuffixStrategy : uint8_t {
  INCREMENTAL = 1,
};

class SuffixStrategy {
 public:
  static constexpr uint32_t MAX_SUFFIX = std::numeric_limits<uint32_t>::max();
  static constexpr uint8_t MANIFEST_MAX_CAPACITY =
      std::numeric_limits<uint8_t>::max();

  SuffixStrategy(NextSuffixStrategy strategy, uint32_t offset = 0,
                 uint32_t manifest_capacity = MANIFEST_MAX_CAPACITY)
      : suffix_stragegy_(strategy),
        next_suffix_(offset),
        manifest_capacity_(manifest_capacity),
        total_count_(0),
        final_suffix_(MAX_SUFFIX) {}

  virtual ~SuffixStrategy() = default;

  virtual uint32_t checkNextSuffix() const = 0;
  virtual uint32_t getNextSuffix() = 0;

  virtual uint32_t checkNextManifestSuffix() const = 0;
  virtual uint32_t getNextManifestSuffix() = 0;

  virtual uint32_t checkNextContentSuffix() const = 0;
  virtual uint32_t getNextContentSuffix() = 0;

  virtual void reset(uint32_t offset = 0) {
    next_suffix_ = offset;
    total_count_ = 0;
  }

  virtual uint32_t getManifestCapacity() const { return manifest_capacity_; };

  virtual void setManifestCapacity(uint8_t capacity) {
    manifest_capacity_ = capacity;
  }

  virtual uint32_t getFinalSuffix() const { return final_suffix_; }

  virtual void setFinalSuffix(std::uint32_t final_suffix) {
    if (final_suffix != MAX_SUFFIX) {
      final_suffix_ = final_suffix;
    }
  }

  NextSuffixStrategy getSuffixStrategy() const { return suffix_stragegy_; }

  virtual uint32_t getTotalCount() const { return total_count_; }

 protected:
  NextSuffixStrategy suffix_stragegy_;
  std::uint32_t next_suffix_;
  std::uint8_t manifest_capacity_;
  std::uint32_t total_count_;
  std::uint32_t final_suffix_;

  inline void incrementTotalCount() { total_count_++; };
};

class IncrementalSuffixStrategy : public SuffixStrategy {
 public:
  IncrementalSuffixStrategy(std::uint32_t start_offset)
      : SuffixStrategy(NextSuffixStrategy::INCREMENTAL, start_offset) {}

  TRANSPORT_ALWAYS_INLINE std::uint32_t checkNextSuffix() const override {
    return next_suffix_;
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextSuffix() override {
    incrementTotalCount();
    return next_suffix_++;
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t checkNextContentSuffix()
      const override {
    return checkNextSuffix();
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextContentSuffix() override {
    return getNextSuffix();
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t checkNextManifestSuffix()
      const override {
    return checkNextSuffix();
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getNextManifestSuffix() override {
    return getNextSuffix();
  }

  void reset(std::uint32_t offset = 0) override { next_suffix_ = offset; }
};

class SuffixStrategyFactory {
 public:
  static std::unique_ptr<SuffixStrategy> getSuffixStrategy(
      NextSuffixStrategy strategy, uint32_t start_offset = 0,
      uint32_t manifest_capacity = SuffixStrategy::MANIFEST_MAX_CAPACITY) {
    switch (strategy) {
      case NextSuffixStrategy::INCREMENTAL:
        return std::make_unique<IncrementalSuffixStrategy>(start_offset);
      default:
        throw errors::RuntimeException(
            "No valid NextSuffixStrategy specified.");
    }
  }
};

}  // namespace utils
