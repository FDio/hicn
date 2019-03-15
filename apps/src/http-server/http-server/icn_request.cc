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

#include "icn_request.h"

namespace icn_httpserver {

IcnRequest::IcnRequest(std::shared_ptr<libl4::http::HTTPServerPublisher>& publisher)
    : publisher_(publisher) {
  time_t t;
  time(&t);
  srand((unsigned int) t);
  request_id_ = rand();
}

IcnRequest::IcnRequest(std::shared_ptr<libl4::http::HTTPServerPublisher>& publisher,
                       std::string name,
                       std::string path,
                       std::string method, std::string http_version)
    : IcnRequest(publisher) {
  this->name_ = name;
  this->path_ = path;
  this->method_ = method;
  this->http_version_ = http_version;
}

const std::string &IcnRequest::getName() const {
  return name_;
}

void IcnRequest::setName(const std::string &name) {
  IcnRequest::name_ = name;
}

int IcnRequest::getRequest_id() const {
  return request_id_;
}

void IcnRequest::setRequest_id(int request_id) {
  IcnRequest::request_id_ = request_id;
}

const std::shared_ptr<libl4::http::HTTPServerPublisher> &IcnRequest::getHttpPublisher() const {
  return publisher_;
}

void IcnRequest::setProducer(const std::shared_ptr<libl4::http::HTTPServerPublisher> &producer) {
  IcnRequest::publisher_ = producer;
}

} // end namespace icn_httpserver
