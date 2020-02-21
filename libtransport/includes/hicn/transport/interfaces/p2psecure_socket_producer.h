/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <hicn/transport/interfaces/socket_producer.h>

#include <hicn/transport/security/identity.h>

namespace transport {

namespace interface {

class P2PSecureProducerSocket : public ProducerSocket {
 public:
  P2PSecureProducerSocket();
  P2PSecureProducerSocket(bool rtc,
                          const std::shared_ptr<utils::Identity> &identity);
  ~P2PSecureProducerSocket() = default;
};

}  // namespace interface

}  // end namespace transport
