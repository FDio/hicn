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

/**
 * Forward on the path with lowest latency
 */

#ifndef lowLatency_h
#define lowLatency_h

#include <hicn/strategies/strategyImpl.h>
#include <hicn/core/forwarder.h>

StrategyImpl *strategyLowLatency_Create();

void strategyLowLatency_GetStrategy(StrategyImpl *strategy,
                                    const Forwarder * forwarder,
                                    const FibEntry * fibEntry,
                                    unsigned * related_prefixes_len,
                                    Name ***related_prefixes);

void strategyLowLatency_SetStrategy(StrategyImpl *strategy,
                                    const Forwarder * forwarder,
                                    const FibEntry * fibEntry,
                                    unsigned related_prefixes_len,
                                    Name **related_prefixes);
#endif  // lowLatency_h
