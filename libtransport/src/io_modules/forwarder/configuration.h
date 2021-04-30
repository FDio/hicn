/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

namespace transport {
namespace core {

struct ListenerConfig {
  std::string address;
  std::uint16_t port;
  std::string name;
};

struct ConnectorConfig {
  std::string local_address;
  std::uint16_t local_port;
  std::string remote_address;
  std::uint16_t remote_port;
  std::string name;
};

struct RouteConfig {
  std::string prefix;
  uint16_t weight;
  std::string connector;
  std::string name;
};

class Configuration {
 public:
  Configuration() : n_threads_(1) {}

  bool empty() {
    return listeners_.empty() && connectors_.empty() && routes_.empty();
  }

  Configuration& setThreadNumber(std::size_t threads) {
    n_threads_ = threads;
    return *this;
  }

  std::size_t getThreadNumber() { return n_threads_; }

  template <typename... Args>
  Configuration& addListener(Args&&... args) {
    listeners_.emplace_back(std::forward<Args>(args)...);
    return *this;
  }

  template <typename... Args>
  Configuration& addConnector(Args&&... args) {
    connectors_.emplace_back(std::forward<Args>(args)...);
    return *this;
  }

  template <typename... Args>
  Configuration& addRoute(Args&&... args) {
    routes_.emplace_back(std::forward<Args>(args)...);
    return *this;
  }

  std::vector<ListenerConfig>& getListeners() { return listeners_; }

  std::vector<ConnectorConfig>& getConnectors() { return connectors_; }

  std::vector<RouteConfig>& getRoutes() { return routes_; }

 private:
  std::vector<ListenerConfig> listeners_;
  std::vector<ConnectorConfig> connectors_;
  std::vector<RouteConfig> routes_;
  std::size_t n_threads_;
};

}  // namespace core
}  // namespace transport