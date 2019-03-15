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

#include "config.h"

#include <string>

#if defined(HICNET)
# include <hicn/transport/http/facade.h>
#elif defined(ICNET)
# include <icnet/icnet_http_facade.h>
#else
# error "No ICN tranport library to which link against."
#endif

class HTTPClient {
 public:
  virtual ~HTTPClient() = default;

  virtual void setTcp() = 0;

  virtual bool download(const std::string &url, std::ostream &out) = 0;
};
