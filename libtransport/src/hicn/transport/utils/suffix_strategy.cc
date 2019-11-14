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

#include <hicn/transport/utils/suffix_strategy.h>

using transport::core::NextSegmentCalculationStrategy;

namespace utils {
std::uint32_t SuffixManifest::getNextSuffix() {
  uint32_t next_suffix;

  switch (suffix_stragegy_) {
    case NextSegmentCalculationStrategy::INCREMENTAL:
      if (!nb_segments_) {
        throw errors::RuntimeException(
            "The number of segments in a manifest must be set "
            "before assigning incremental suffixes.");
      }
      /* The current manifest's suffix + the number of segments in a */
      /* manifest give the suffix of the last segment in the manifest. */
      /* The next manifest's suffix is therefore that number plus one. */
      next_suffix = suffix_ + nb_segments_ + 1;
      break;

    default:
      throw errors::RuntimeException("Unknown suffix strategy.");
  }

  return next_suffix;
}

std::uint32_t SuffixContent::getNextSuffix() {
  uint32_t next_suffix;

  switch (suffix_stragegy_) {
    case NextSegmentCalculationStrategy::INCREMENTAL:
      next_suffix = suffix_ + 1;
      if (making_manifest_) {
        if (!nb_segments_) {
          throw errors::RuntimeException(
              "The number of segments in a manifest must be set "
              "before assigning incremental suffixes.");
        }

        content_counter_++;
        /* If the counter have reached the manifest's capacity,
         * it means that the next suffix will be a manifest, so we skip it. */
        if (content_counter_ % nb_segments_ == 0) {
          next_suffix++;
          content_counter_ = 0;
        }
      }
      break;

    default:
      throw errors::RuntimeException("Unknown suffix strategy.");
  }

  return next_suffix;
}
}  // namespace utils
