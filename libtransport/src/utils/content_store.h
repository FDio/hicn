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

#include <hicn/transport/utils/spinlock.h>

#include <mutex>

namespace transport {

namespace core {
class Name;
class ContentObject;
class Interest;
}  // namespace core

}  // namespace transport

namespace utils {

using Name = transport::core::Name;
using ContentObject = transport::core::ContentObject;
using Interest = transport::core::Interest;

typedef std::pair<std::shared_ptr<ContentObject>,
                  std::chrono::steady_clock::time_point>
    ObjectTimeEntry;
typedef std::pair<ObjectTimeEntry,
                  std::list<std::reference_wrapper<const Name>>::iterator>
    ContentStoreEntry;
typedef std::list<std::reference_wrapper<const Name>> FIFOList;
typedef std::unordered_map<Name, ContentStoreEntry> ContentStoreHashTable;

class ContentStore {
 public:
  explicit ContentStore(std::size_t max_packets = (1 << 16));

  ~ContentStore();

  void insert(const std::shared_ptr<ContentObject> &content_object);

  const std::shared_ptr<ContentObject> find(const Interest &interest);

  void erase(const Name &exact_name);

  void setLimit(size_t max_packets);

  size_t getLimit() const;

  size_t size() const;

  void printContent();

 private:
  ContentStoreHashTable content_store_hash_table_;
  FIFOList fifo_list_;
  std::shared_ptr<ContentObject> empty_reference_;
  // Must be atomic
  std::atomic_size_t max_content_store_size_;
  mutable utils::SpinLock cs_mutex_;
};

}  // end namespace utils