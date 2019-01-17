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

#ifndef nexthopstatewithpd_h
#define nexthopstatewithpd_h

#include <parc/algol/parc_HashCode.h>
#include <parc/algol/parc_Object.h>

struct strategy_nexthop_state_with_pd;
typedef struct strategy_nexthop_state_with_pd StrategyNexthopStateWithPD;
extern parcObjectDescriptor_Declaration(StrategyNexthopStateWithPD);

/**
 */
StrategyNexthopStateWithPD *strategyNexthopStateWithPD_Acquire(const StrategyNexthopStateWithPD *instance);

#ifdef PARCLibrary_DISABLE_VALIDATION
#  define strategyNexthopStateWithPD_OptionalAssertValid(_instance_)
#else
#  define strategyNexthopStateWithPD_OptionalAssertValid(_instance_) strategyNexthopStateWithPD_AssertValid(_instance_)
#endif

/**
 */
void strategyNexthopStateWithPD_AssertValid(const StrategyNexthopStateWithPD *instance);

/**
 */
StrategyNexthopStateWithPD *strategyNexthopStateWithPD_Create();

void strategyNexthopStateWithPD_Reset(StrategyNexthopStateWithPD *x);
/**
 */
int strategyNexthopStateWithPD_Compare(const StrategyNexthopStateWithPD *instance, const StrategyNexthopStateWithPD *other);

/**
 */
StrategyNexthopStateWithPD *strategyNexthopStateWithPD_Copy(const StrategyNexthopStateWithPD *original);

/**
 */
void strategyNexthopStateWithPD_Display(const StrategyNexthopStateWithPD *instance, int indentation);

/**
 */
bool strategyNexthopStateWithPD_Equals(const StrategyNexthopStateWithPD *x, const StrategyNexthopStateWithPD *y);

/**
 */
PARCHashCode strategyNexthopStateWithPD_HashCode(const StrategyNexthopStateWithPD *instance);

/**
 */
bool strategyNexthopStateWithPD_IsValid(const StrategyNexthopStateWithPD *instance);

/**
 */
void strategyNexthopStateWithPD_Release(StrategyNexthopStateWithPD **instancePtr);

/**
 */
char *strategyNexthopStateWithPD_ToString(const StrategyNexthopStateWithPD *instance);

/**
 */
unsigned strategyNexthopStateWithPD_GetPI(const StrategyNexthopStateWithPD *x);

double strategyNexthopStateWithPD_GetAvgPI(const StrategyNexthopStateWithPD *x);

double strategyNexthopStateWithPD_GetWeight(const StrategyNexthopStateWithPD *x);

unsigned strategyNexthopStateWithPD_GetDelay(const StrategyNexthopStateWithPD *x);
void strategyNexthopStateWithPD_SetDelay(StrategyNexthopStateWithPD *x, unsigned delay);

double strategyNexthopStateWithPD_UpdateState(StrategyNexthopStateWithPD *x, bool inc, unsigned min_delay, double alpha); 
#endif
