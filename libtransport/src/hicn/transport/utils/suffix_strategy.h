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

#include <hicn/transport/core/manifest_format.h>

namespace utils {
class SuffixStrategy {
 public:
  SuffixStrategy(
      transport::core::NextSegmentCalculationStrategy suffix_stragegy,
      std::uint32_t start_offset)
      : suffix_stragegy_(suffix_stragegy),
        suffix_(start_offset),
        nb_segments_(0) {}

  transport::core::NextSegmentCalculationStrategy getSuffixStrategy() {
    return suffix_stragegy_;
  }

  std::uint32_t getSuffix() { return suffix_; }

  virtual std::uint32_t getNextSuffix() = 0;

  void updateSuffix(std::uint32_t new_suffix) { suffix_ = new_suffix; }

  std::size_t getNbSegments() { return nb_segments_; }

  void setNbSegments(std::size_t nb_segments) { nb_segments_ = nb_segments; }

  void reset(std::uint32_t reset_suffix) {
    suffix_ = reset_suffix;
    nb_segments_ = 0;
  }

  ~SuffixStrategy() {}

 protected:
  transport::core::NextSegmentCalculationStrategy suffix_stragegy_;
  std::uint32_t suffix_;
  std::size_t nb_segments_;
};

class SuffixManifest : public SuffixStrategy {
 public:
  SuffixManifest(
      transport::core::NextSegmentCalculationStrategy suffix_stragegy,
      std::uint32_t start_offset)
      : SuffixStrategy(suffix_stragegy, start_offset) {}

  std::uint32_t getNextSuffix();

  SuffixManifest operator++() {
    uint32_t next_suffix = getNextSuffix();
    updateSuffix(next_suffix);
    return SuffixManifest(suffix_stragegy_, next_suffix);
  }

  SuffixManifest operator++(int) {
    SuffixManifest temp_suffix(suffix_stragegy_, suffix_);
    uint32_t next_suffix = getNextSuffix();
    updateSuffix(next_suffix);
    return temp_suffix;
  }

  SuffixManifest operator+(uint32_t shift) {
    for (uint32_t i = 0; i < shift; i++) {
      updateSuffix(getNextSuffix());
    }
    return SuffixManifest(suffix_stragegy_, getSuffix());
  }
};

class SuffixContent : public SuffixStrategy {
 public:
  SuffixContent(transport::core::NextSegmentCalculationStrategy suffix_stragegy,
                std::uint32_t start_offset, bool making_manifest)
      : SuffixStrategy(suffix_stragegy, start_offset),
        making_manifest_(making_manifest),
        content_counter_(0) {}

  SuffixContent(transport::core::NextSegmentCalculationStrategy suffix_stragegy,
                std::uint32_t start_offset)
      : SuffixContent(suffix_stragegy, start_offset, false) {}

  std::uint32_t getNextSuffix();

  SuffixContent operator++() {
    uint32_t next_suffix = getNextSuffix();
    updateSuffix(next_suffix);
    return SuffixContent(suffix_stragegy_, next_suffix, making_manifest_);
  }

  SuffixContent operator++(int) {
    SuffixContent temp_suffix(suffix_stragegy_, suffix_, making_manifest_);
    uint32_t next_suffix = getNextSuffix();
    updateSuffix(next_suffix);
    return temp_suffix;
  }

  SuffixContent operator+(uint32_t shift) {
    for (uint32_t i = 0; i < shift; i++) {
      updateSuffix(getNextSuffix());
    }
    return SuffixContent(suffix_stragegy_, getSuffix(), making_manifest_);
  }

  void setUsingManifest(bool value) { making_manifest_ = value; }

  void reset(std::uint32_t reset_suffix) {
    SuffixStrategy::reset(reset_suffix);
    content_counter_ = 0;
  }

 protected:
  bool making_manifest_;
  /* content_counter_ keeps track of the number of segments */
  /* between two manifests */
  uint32_t content_counter_;
};
}  // namespace utils
