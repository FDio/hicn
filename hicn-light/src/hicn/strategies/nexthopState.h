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

#ifndef nexthopstate_h
#define nexthopstate_h

#include <parc/algol/parc_HashCode.h>
#include <parc/algol/parc_Object.h>

struct strategy_nexthop_state;
typedef struct strategy_nexthop_state StrategyNexthopState;
extern parcObjectDescriptor_Declaration(StrategyNexthopState);

/**
 */
StrategyNexthopState *strategyNexthopState_Acquire(
    const StrategyNexthopState *instance);

#ifdef PARCLibrary_DISABLE_VALIDATION
#define strategyNexthopState_OptionalAssertValid(_instance_)
#else
#define strategyNexthopState_OptionalAssertValid(_instance_) \
  strategyNexthopState_AssertValid(_instance_)
#endif

/**
 */
void strategyNexthopState_AssertValid(const StrategyNexthopState *instance);

/**
 */
StrategyNexthopState *strategyNexthopState_Create();

void strategyNexthopState_Reset(StrategyNexthopState *x);
/**
 */
int strategyNexthopState_Compare(const StrategyNexthopState *instance,
                                 const StrategyNexthopState *other);

/**
 */
StrategyNexthopState *strategyNexthopState_Copy(
    const StrategyNexthopState *original);

/**
 */
void strategyNexthopState_Display(const StrategyNexthopState *instance,
                                  int indentation);

/**
 */
bool strategyNexthopState_Equals(const StrategyNexthopState *x,
                                 const StrategyNexthopState *y);

/**
 */
PARCHashCode strategyNexthopState_HashCode(
    const StrategyNexthopState *instance);

/**
 */
bool strategyNexthopState_IsValid(const StrategyNexthopState *instance);

/**
 */
void strategyNexthopState_Release(StrategyNexthopState **instancePtr);

/**
 */
char *strategyNexthopState_ToString(const StrategyNexthopState *instance);

/**
 */
unsigned strategyNexthopState_GetPI(const StrategyNexthopState *x);

double strategyNexthopState_GetAvgPI(const StrategyNexthopState *x);

double strategyNexthopState_GetWeight(const StrategyNexthopState *x);

double strategyNexthopState_UpdateState(StrategyNexthopState *x, bool inc,
                                        double alpha);
#endif
