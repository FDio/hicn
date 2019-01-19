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

#include <hicn/transport/core/key_locator_type.h>
#include <hicn/transport/core/name.h>

namespace transport {

namespace core {

class KeyLocator : public std::enable_shared_from_this<KeyLocator> {
 public:
  KeyLocator();

  KeyLocator(KeyLocatorType type, Name &name);

  KeyLocatorType getType();

  void setType(KeyLocatorType type);

  void setName(Name &name);

  Name &getName();

  void clear();

 private:
  KeyLocatorType type_;
  Name name_;
};

}  // end namespace core

}  // end namespace transport
