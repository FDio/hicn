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

#include <stdio.h>
#include <src/config.h>
#include <float.h>
#include <limits.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_DisplayIndented.h>
#include <parc/assert/parc_Assert.h>

#include <src/strategies/nexthopStateWithPD.h>

struct strategy_nexthop_state_with_pd {
    unsigned int pi;
    unsigned delay;
    double weight;
    double avg_pi;
};

static bool
_strategyNexthopStateWithPD_Destructor(StrategyNexthopStateWithPD **instancePtr)
{
    return true;
}

parcObject_ImplementAcquire(strategyNexthopStateWithPD, StrategyNexthopStateWithPD);

parcObject_ImplementRelease(strategyNexthopStateWithPD, StrategyNexthopStateWithPD);

parcObject_Override(StrategyNexthopStateWithPD, PARCObject,
                    .destructor = (PARCObjectDestructor *) _strategyNexthopStateWithPD_Destructor,
                    .copy = (PARCObjectCopy *) strategyNexthopStateWithPD_Copy,
                    .display = (PARCObjectDisplay *) strategyNexthopStateWithPD_Display,
                    .toString = (PARCObjectToString *) strategyNexthopStateWithPD_ToString,
                    .equals = (PARCObjectEquals *) strategyNexthopStateWithPD_Equals,
                    .compare = (PARCObjectCompare *) strategyNexthopStateWithPD_Compare,
                    .hashCode = (PARCObjectHashCode *) strategyNexthopStateWithPD_HashCode,
                    .display = (PARCObjectDisplay *) strategyNexthopStateWithPD_Display);

void
strategyNexthopStateWithPD_AssertValid(const StrategyNexthopStateWithPD *instance)
{
    parcAssertTrue(strategyNexthopStateWithPD_IsValid(instance),
               "StrategyNexthopStateWithPD is not valid.");
}

StrategyNexthopStateWithPD *
strategyNexthopStateWithPD_Create()
{
    StrategyNexthopStateWithPD *result = parcObject_CreateInstance(StrategyNexthopStateWithPD);
    if (result != NULL) {
        result->pi = 0;
        result->avg_pi = 1.0;
        result->weight = 1;
        result->delay = 0;
    }
    return result;
}

void
strategyNexthopStateWithPD_Reset(StrategyNexthopStateWithPD *x)
{
    x->pi = 0;
    x->avg_pi = 1.0;
    x->weight = 1;
    x->delay = 0;
}

int
strategyNexthopStateWithPD_Compare(const StrategyNexthopStateWithPD *val, const StrategyNexthopStateWithPD *other)
{
    if (val == NULL) {
        if (other != NULL) {
            return -1;
        }
    } else if (other == NULL) {
        return 1;
    } else {
        strategyNexthopStateWithPD_OptionalAssertValid(val);
        strategyNexthopStateWithPD_OptionalAssertValid(other);

        if (val->pi < other->pi) {
            return -1;
        } else if (val->pi > other->pi) {
            return 1;
        }

        if (val->avg_pi < other->avg_pi) {
            return -1;
        } else if (val->avg_pi > other->avg_pi) {
            return 1;
        }

        if (val->weight < other->weight) {
            return -1;
        } else if (val->weight > other->weight) {
            return 1;
        }

        if (val->delay < other->delay) {
            return -1;
        } else if (val->delay > other->delay) {
            return 1;
        }
    }

    return 0;
}

StrategyNexthopStateWithPD *
strategyNexthopStateWithPD_Copy(const StrategyNexthopStateWithPD *original)
{
    StrategyNexthopStateWithPD *result = strategyNexthopStateWithPD_Create();
    result->pi = original->pi;
    result->avg_pi = original->avg_pi;
    result->weight = original->weight;
    result->delay = original->delay;

    return result;
}

void
strategyNexthopStateWithPD_Display(const StrategyNexthopStateWithPD *instance, int indentation)
{
    parcDisplayIndented_PrintLine(indentation, "StrategyNexthopStateWithPD@%p {", instance);
    parcDisplayIndented_PrintLine(indentation + 1, "%d", instance->pi);
    parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->avg_pi);
    parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->weight);
    parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->delay);
    parcDisplayIndented_PrintLine(indentation, "}");
}

bool
strategyNexthopStateWithPD_Equals(const StrategyNexthopStateWithPD *x, const StrategyNexthopStateWithPD *y)
{
    bool result = false;

    if (x == y) {
        result = true;
    } else if (x == NULL || y == NULL) {
        result = false;
    } else {
        strategyNexthopStateWithPD_OptionalAssertValid(x);
        strategyNexthopStateWithPD_OptionalAssertValid(y);

        if (strategyNexthopStateWithPD_Compare(x, y) == 0) {
            result = true;
        }
    }

    return result;
}

PARCHashCode
strategyNexthopStateWithPD_HashCode(const StrategyNexthopStateWithPD *x)
{
    PARCHashCode result = 0;
    char str[128];
    sprintf(str, "PI:%d: AVG_PI:%f: W:%f D:%d", x->pi, x->avg_pi, x->weight, x->delay);
    result = parcHashCode_Hash((uint8_t *) &str, strlen(str));
    return result;
}

bool
strategyNexthopStateWithPD_IsValid(const StrategyNexthopStateWithPD *x)
{
    bool result = false;

    if (x != NULL) {
        result = true;
    }

    return result;
}

char *
strategyNexthopStateWithPD_ToString(const StrategyNexthopStateWithPD *x)
{
    //this is not implemented
     parcTrapNotImplemented("strategyNexthopStateWithPD_ToString is not implemented");
    return NULL;
}

unsigned
strategyNexthopStateWithPD_GetPI(const StrategyNexthopStateWithPD *x)
{
    strategyNexthopStateWithPD_OptionalAssertValid(x);

    return x->pi;
}

double
strategyNexthopStateWithPD_GetAvgPI(const StrategyNexthopStateWithPD *x)
{
    strategyNexthopStateWithPD_OptionalAssertValid(x);

    return x->avg_pi;
}

double
strategyNexthopStateWithPD_GetWeight(const StrategyNexthopStateWithPD *x)
{
    strategyNexthopStateWithPD_OptionalAssertValid(x);

    return x->weight;
}

unsigned
strategyNexthopStateWithPD_GetDelay(const StrategyNexthopStateWithPD *x)
{
    strategyNexthopStateWithPD_OptionalAssertValid(x);

    return x->delay;
}

void
strategyNexthopStateWithPD_SetDelay(StrategyNexthopStateWithPD *x, unsigned delay)
{
    strategyNexthopStateWithPD_OptionalAssertValid(x);
    if (delay != 0) {
        x->delay = delay;
    }
}

double
strategyNexthopStateWithPD_UpdateState(StrategyNexthopStateWithPD *x, bool inc, unsigned min_delay, double alpha)
{
    strategyNexthopStateWithPD_OptionalAssertValid(x);

    if (inc) {
        x->pi++;
    } else  {
        if (x->pi > 0) {
            x->pi--;
        }
    }

    x->avg_pi = (x->avg_pi * alpha) + (x->pi * (1 - alpha));
    if (x->avg_pi == 0.0) {
        x->avg_pi = 0.1;
    }

    double factor = 1.0;
    if (min_delay != INT_MAX && x->delay != 0) {
        factor = ((double) min_delay / (double) x->delay);
    }

    x->weight = 1 / (x->avg_pi * factor);

    return x->weight;
}

