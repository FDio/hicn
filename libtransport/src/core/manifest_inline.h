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

#include <hicn/transport/portability/portability.h>

#include <core/manifest.h>
#include <core/manifest_format.h>
#include <set>

namespace transport {

namespace core {

template <typename Base, typename FormatTraits>
class ManifestInline
    : public Manifest<Base, FormatTraits, ManifestInline<Base, FormatTraits>> {
  using ManifestBase =
      Manifest<Base, FormatTraits, ManifestInline<Base, FormatTraits>>;
  using HashType = typename FormatTraits::HashType;
  using SuffixList = typename FormatTraits::SuffixList;

 public:
  ManifestInline() : ManifestBase() {}

  ManifestInline(const core::Name &name, std::size_t signature_size = 0)
      : ManifestBase(name, signature_size) {}

  template <typename T>
  ManifestInline(T &&base) : ManifestBase(std::forward<T &&>(base)) {}

  static TRANSPORT_ALWAYS_INLINE ManifestInline *createManifest(
      const core::Name &manifest_name, ManifestVersion version,
      ManifestType type, HashAlgorithm algorithm, bool is_last,
      const Name &base_name, NextSegmentCalculationStrategy strategy,
      std::size_t signature_size) {
    auto manifest = new ManifestInline(manifest_name, signature_size);
    manifest->setVersion(version);
    manifest->setManifestType(type);
    manifest->setHashAlgorithm(algorithm);
    manifest->setFinalManifest(is_last);
    manifest->setBaseName(base_name);
    manifest->setNextSegmentCalculationStrategy(strategy);

    return manifest;
  }

  ManifestInline &encodeImpl() {
    ManifestBase::encoder_.encode();
    return *this;
  }

  ManifestInline &decodeImpl() {
    base_name_ = ManifestBase::decoder_.getBaseName();
    next_segment_strategy_ =
        ManifestBase::decoder_.getNextSegmentCalculationStrategy();
    suffix_hash_map_ = ManifestBase::decoder_.getSuffixHashList();

    return *this;
  }

  std::size_t estimateManifestSizeImpl(std::size_t additional_entries = 0) {
    return ManifestBase::encoder_.estimateSerializedLength(additional_entries);
  }

  ManifestInline &setBaseName(const Name &name) {
    base_name_ = name;
    ManifestBase::encoder_.setBaseName(base_name_);
    return *this;
  }

  const Name &getBaseName() { return base_name_; }

  ManifestInline &addSuffixHash(uint32_t suffix, const HashType &hash) {
    ManifestBase::encoder_.addSuffixAndHash(suffix, hash);
    return *this;
  }

  // Call this function only after the decode function!
  const SuffixList &getSuffixList() { return suffix_hash_map_; }

  ManifestInline &setNextSegmentCalculationStrategy(
      NextSegmentCalculationStrategy strategy) {
    next_segment_strategy_ = strategy;
    ManifestBase::encoder_.setNextSegmentCalculationStrategy(
        next_segment_strategy_);
    return *this;
  }

  NextSegmentCalculationStrategy getNextSegmentCalculationStrategy() {
    return next_segment_strategy_;
  }

 private:
  core::Name base_name_;
  NextSegmentCalculationStrategy next_segment_strategy_;
  SuffixList suffix_hash_map_;
};

}  // end namespace core

}  // end namespace transport