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

#include "config.h"

#if defined(HICNET)
#include <hicn/transport/http/facade.h>
#include <hicn/transport/utils/hash.h>
#elif defined(ICNET)
#include <icnet/icnet_http_facade.h>
#include <icnet/icnet_utils_hash.h>
#else
#error "No ICN tranport library to which link against."
#endif

#include <algorithm>
#include <asio.hpp>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>

typedef asio::ip::tcp::socket socket_type;
typedef std::function<void(const std::error_code &)> SendCallback;
