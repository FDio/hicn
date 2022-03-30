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

#ifndef nexthopstateLowLatency_h
#define nexthopstateLowLatency_h

#include <parc/algol/parc_HashCode.h>
#include <parc/algol/parc_Object.h>

struct strategy_nexthop_state_ll;
typedef struct strategy_nexthop_state_ll StrategyNexthopStateLL;
extern parcObjectDescriptor_Declaration(StrategyNexthopStateLL);

/**
 */
StrategyNexthopStateLL *strategyNexthopStateLL_Acquire(
    const StrategyNexthopStateLL *instance);

#ifdef PARCLibrary_DISABLE_VALIDATION
#define strategyNexthopStateLL_OptionalAssertValid(_instance_)
#else
#define strategyNexthopStateLL_OptionalAssertValid(_instance_) \
  strategyNexthopStateLL_AssertValid(_instance_)
#endif

/**
 */
void strategyNexthopStateLL_AssertValid(const StrategyNexthopStateLL *instance);

/**
 */
StrategyNexthopStateLL *strategyNexthopStateLL_Create(unsigned face_id);

void strategyNexthopStateLL_Reset(StrategyNexthopStateLL *x);
/**
 */
int strategyNexthopStateLL_Compare(const StrategyNexthopStateLL *instance,
                                   const StrategyNexthopStateLL *other);

/**
 */
StrategyNexthopStateLL *strategyNexthopStateLL_Copy(
    const StrategyNexthopStateLL *original);

/**
 */
void strategyNexthopStateLL_Display(const StrategyNexthopStateLL *instance,
                                    int indentation);

/**
 */
bool strategyNexthopStateLL_Equals(const StrategyNexthopStateLL *x,
                                   const StrategyNexthopStateLL *y);

/**
 */
PARCHashCode strategyNexthopStateLL_HashCode(
    const StrategyNexthopStateLL *instance);

/**
 */
bool strategyNexthopStateLL_IsValid(const StrategyNexthopStateLL *instance);

/**
 */
void strategyNexthopStateLL_Release(StrategyNexthopStateLL **instancePtr);

/**
 */
char *strategyNexthopStateLL_ToString(const StrategyNexthopStateLL *instance);

/**
 */
double strategyNexthopStateLL_GetRTTProbe(StrategyNexthopStateLL *x);
double strategyNexthopStateLL_GetRTTInUse(StrategyNexthopStateLL *x);
double strategyNexthopStateLL_GetRTTLive(StrategyNexthopStateLL *x);
double strategyNexthopStateLL_GetQueuing(const StrategyNexthopStateLL *x);
void strategyNexthopStateLL_AddRttSample(StrategyNexthopStateLL *x,
                                         unsigned int rtt);

void strategyNexthopStateLL_IncreaseTryToSwitch(StrategyNexthopStateLL *x,
                                                unsigned round);
unsigned strategyNexthopStateLL_GetTryToSwitch(const StrategyNexthopStateLL *x);
void strategyNexthopStateLL_ResetTryToSwitch(StrategyNexthopStateLL *x);

void strategyNexthopStateLL_SetUnusedFace(StrategyNexthopStateLL *x);

unsigned strategyNexthopStateLL_GetFaceId(StrategyNexthopStateLL *x);

void strategyNexthopStateLL_SendPacket(StrategyNexthopStateLL *x);

void strategyNexthopStateLL_SentProbe(StrategyNexthopStateLL *x);

void strategyNexthopStateLL_LostProbe(StrategyNexthopStateLL *x);

bool strategyNexthopStateLL_IsLossy(const StrategyNexthopStateLL *x);

void strategyNexthopStateLL_SetIsAllowed(StrategyNexthopStateLL *x,
                                         bool allowed);

bool strategyNexthopStateLL_IsAllowed(const StrategyNexthopStateLL *x);

void strategyNexthopStateLL_StartNewRound(StrategyNexthopStateLL *x);
#endif
