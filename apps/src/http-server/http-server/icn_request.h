/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include "common.h"
#include "request.h"

namespace icn_httpserver {

class IcnRequest
    : public Request {
 public:
  IcnRequest(std::shared_ptr<libl4::http::HTTPServerPublisher>& publisher);

  IcnRequest(std::shared_ptr<libl4::http::HTTPServerPublisher>& publisher,
             std::string name,
             std::string path,
             std::string method,
             std::string http_version);

  ~IcnRequest() = default;

  const std::string &getName() const;

  void setName(const std::string &name);

  int getRequest_id() const;

  void setRequest_id(int request_id);

  const std::shared_ptr<libl4::http::HTTPServerPublisher> &getHttpPublisher() const;

  void setProducer(const std::shared_ptr<libl4::http::HTTPServerPublisher> &producer);

 private:
  std::string name_;
  int request_id_;
  std::shared_ptr<libl4::http::HTTPServerPublisher> publisher_;

};

} // end namespace icn_httpserver