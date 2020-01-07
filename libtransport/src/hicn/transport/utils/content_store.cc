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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/utils/content_store.h>

namespace utils {

ContentStore::ContentStore(std::size_t max_packets)
    : max_content_store_size_(max_packets) {}

ContentStore::~ContentStore() {}

void ContentStore::insert(
    const std::shared_ptr<ContentObject> &content_object) {
  if (max_content_store_size_ == 0) {
    return;
  }

  utils::SpinLock::Acquire locked(cs_mutex_);

  if (TRANSPORT_EXPECT_FALSE(content_store_hash_table_.size() !=
                             fifo_list_.size())) {
    TRANSPORT_LOGW("Inconsistent size!!!!");
    TRANSPORT_LOGW("Hash Table: %zu |||| FIFO List: %zu",
                   content_store_hash_table_.size(), fifo_list_.size());
  }

  if (content_store_hash_table_.size() >= max_content_store_size_) {
    content_store_hash_table_.erase(fifo_list_.back());
    fifo_list_.pop_back();
  }

  // Insert new item
  auto it = content_store_hash_table_.find(content_object->getName());
  if (it != content_store_hash_table_.end()) {
    fifo_list_.erase(it->second.second);
    content_store_hash_table_.erase(content_object->getName());
  }

  fifo_list_.push_front(std::cref(content_object->getName()));
  auto pos = fifo_list_.begin();
  content_store_hash_table_[content_object->getName()] = ContentStoreEntry(
      ObjectTimeEntry(content_object, std::chrono::steady_clock::now()), pos);
}

const std::shared_ptr<ContentObject> ContentStore::find(
    const Interest &interest) {
  utils::SpinLock::Acquire locked(cs_mutex_);

  std::shared_ptr<ContentObject> ret = empty_reference_;
  auto it = content_store_hash_table_.find(interest.getName());
  if (it != content_store_hash_table_.end()) {

    auto content_lifetime = it->second.first.first->getLifetime();
    auto time_passed_since_creation =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - it->second.first.second)
            .count();

    if (time_passed_since_creation > content_lifetime) {
      fifo_list_.erase(it->second.second);
      content_store_hash_table_.erase(it);
    }
    else {
      ret = it->second.first.first;
    }
  }

  return ret;
}

void ContentStore::erase(const Name &exact_name) {
  utils::SpinLock::Acquire locked(cs_mutex_);
  auto it = content_store_hash_table_.find(exact_name);
  fifo_list_.erase(it->second.second);
  content_store_hash_table_.erase(exact_name);
}

void ContentStore::setLimit(size_t max_packets) {
  utils::SpinLock::Acquire locked(cs_mutex_);
  max_content_store_size_ = max_packets;
}

std::size_t ContentStore::getLimit() const {
  utils::SpinLock::Acquire locked(cs_mutex_);
  return max_content_store_size_;
}

std::size_t ContentStore::size() const {
  utils::SpinLock::Acquire locked(cs_mutex_);
  return content_store_hash_table_.size();
}

void ContentStore::printContent() {
  for (auto &item : content_store_hash_table_) {
    if (item.second.first.first->getPayloadType() ==
        transport::core::PayloadType::MANIFEST) {
      TRANSPORT_LOGI("Manifest: %s",
                     item.second.first.first->getName().toString().c_str());
    } else {
      TRANSPORT_LOGI("Data Packet: %s",
                     item.second.first.first->getName().toString().c_str());
    }
  }
}

}  // end namespace utils