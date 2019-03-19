/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "response.h"

namespace icn_httpserver {

class IcnResponse : public Response {

public:
  IcnResponse(std::shared_ptr<libl4::http::HTTPServerPublisher> producer,
              std::string ndn_name, std::string ndn_path);

  void send(const SendCallback &callback = nullptr) override;

  void setResponseLifetime(
      const std::chrono::milliseconds &response_lifetime) override;

private:
  std::string ndn_name_;
  std::string ndn_path_;
  std::shared_ptr<libl4::http::HTTPServerPublisher> publisher_;
};

} // end namespace icn_httpserver
