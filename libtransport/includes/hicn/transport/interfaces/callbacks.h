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

#include <hicn/transport/auth/policies.h>
#include <hicn/transport/interfaces/notification.h>
#include <hicn/transport/interfaces/statistics.h>

#include <functional>
#include <system_error>

namespace utils {
class MemBuf;
}

namespace transport {

namespace protocol {

class IcnObserver;

}  // namespace protocol

namespace core {
class ContentObject;
class Interest;
}  // namespace core

namespace interface {

// Forward declarations
class ConsumerSocket;
class ProducerSocket;

/**
 * The ConsumerInterestCallback will be called in different parts of the
 * consumer socket processing pipeline, with a ConsumerSocket and an Interest as
 * parameters.
 */
using ConsumerInterestCallback =
    std::function<void(ConsumerSocket &, const core::Interest &)>;

/**
 * The ConsumerTimerCallback is called periodically for exposing to applications
 * a summary of the statistics of the transport protocol in use.
 */
using ConsumerTimerCallback =
    std::function<void(ConsumerSocket &, const TransportStatistics &stats)>;

/**
 * The ConsumerTimerCallback is called when the forwarding/recovery stategy is
 * changes.
 */
using StrategyCallback = std::function<void(notification::Strategy strategy)>;

/**
 * The ProducerContentCallback will be called by the producer socket right after
 * a content has been segmented and published.
 */
using ProducerContentCallback = std::function<void(
    ProducerSocket &, const std::error_code &, uint64_t bytes_written)>;

/**
 * The ConsumerContentObjectCallback will be called in different parts of the
 * consumer socket processing pipeline, with a ConsumerSocket and an
 * ContentObject as parameters.
 */
using ConsumerContentObjectCallback =
    std::function<void(ConsumerSocket &, const core::ContentObject &)>;

/**
 * The ProducerContentObjectCallback will be called in different parts of the
 * consumer socket processing pipeline, with a ProducerSocket and an
 * ContentObject as parameters.
 */
using ProducerContentObjectCallback =
    std::function<void(ProducerSocket &, core::ContentObject &)>;

/**
 * The ProducerContentObjectCallback will be called in different parts of the
 * consumer socket processing pipeline, with a ProducerSocket and an
 * Interest as parameters.
 */
using ProducerInterestCallback =
    std::function<void(ProducerSocket &, core::Interest &)>;

extern std::nullptr_t VOID_HANDLER;

}  // namespace interface

}  // namespace transport
