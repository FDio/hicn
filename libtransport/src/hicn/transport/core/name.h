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
#include <hicn/transport/utils/branch_prediction.h>

#include <list>
#include <memory>
#include <string>
#include <unordered_map>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
};

#include <vector>

namespace transport {

namespace core {

typedef struct sockaddr_in6 Sockaddr6;
typedef struct sockaddr_in Sockaddr4;
typedef struct sockaddr Sockaddr;

enum class HashAlgorithm : uint8_t;

class Name {
  friend class Packet;
  friend class ContentObject;
  friend class Interest;

  static const uint32_t standard_name_string_length = 100;

 public:
  using NameStruct = hicn_name_t;
  using Type = hicn_name_type_t;

  Name();

  /**
   * @brief Create name
   * @param name The null-terminated URI string
   */
  Name(const char *name, uint32_t segment);

  Name(int family, const uint8_t *ip_address, std::uint32_t suffix = 0);

  Name(const std::string &uri, uint32_t segment);

  Name(const std::string &uri);

  Name(const Name &name, bool hard_copy = false);

  Name(Name &&name);

  Name &operator=(const Name &name);

  bool operator==(const Name &name) const;

  bool operator!=(const Name &name) const;

  operator bool() const;

  std::string toString() const;

  bool equals(const Name &name, bool consider_segment = true) const;

  uint32_t getHash32() const;

  void clear();

  Type getType() const;

  uint32_t getSuffix() const;

  std::shared_ptr<Sockaddr> getAddress() const;

  Name &setSuffix(uint32_t seq_number);

  ip_address_t toIpAddress() const;

  void copyToDestination(uint8_t *destination,
                         bool include_suffix = false) const;

  int getAddressFamily() const;

 private:
  TRANSPORT_ALWAYS_INLINE NameStruct *getStructReference() const {
    if (TRANSPORT_EXPECT_TRUE(name_ != nullptr)) {
      return name_.get();
    }

    return nullptr;
  }

  static TRANSPORT_ALWAYS_INLINE std::unique_ptr<NameStruct> createEmptyName() {
    NameStruct *name = new NameStruct;
    name->type = HNT_UNSPEC;
    return std::unique_ptr<NameStruct>(name);
  };

  std::unique_ptr<NameStruct> name_;
};

std::ostream &operator<<(std::ostream &os, const Name &name);

}  // end namespace core

}  // end namespace transport

namespace std {
template <>
struct hash<transport::core::Name> {
  size_t operator()(const transport::core::Name &name) const;
};

}  // end namespace std
