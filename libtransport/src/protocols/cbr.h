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

#include <protocols/raaqm.h>

namespace transport {

namespace protocol {

class CbrTransportProtocol : public RaaqmTransportProtocol {
 public:
  CbrTransportProtocol(implementation::ConsumerSocket *icnet_socket);

  int start() override;

  void reset() override;

 private:
  void afterContentReception(const Interest &interest,
                             const ContentObject &content_object) override;
  void afterDataUnsatisfied(uint64_t segment) override;
};

}  // end namespace protocol

}  // end namespace transport