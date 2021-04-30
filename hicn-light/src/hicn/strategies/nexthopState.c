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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <parc/algol/parc_DisplayIndented.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>

#include <parc/assert/parc_Assert.h>
#include <hicn/strategies/nexthopState.h>

#define AVG_PI_THRESHOLD 1e-3

struct strategy_nexthop_state {
  unsigned int pi;
  double avg_pi;
  double weight;
};

static bool _strategyNexthopState_Destructor(
    StrategyNexthopState **instancePtr) {
  return true;
}

parcObject_ImplementAcquire(strategyNexthopState, StrategyNexthopState);

parcObject_ImplementRelease(strategyNexthopState, StrategyNexthopState);

parcObject_Override(
    StrategyNexthopState, PARCObject,
    .destructor = (PARCObjectDestructor *)_strategyNexthopState_Destructor,
    .copy = (PARCObjectCopy *)strategyNexthopState_Copy,
    .display = (PARCObjectDisplay *)strategyNexthopState_Display,
    .toString = (PARCObjectToString *)strategyNexthopState_ToString,
    .equals = (PARCObjectEquals *)strategyNexthopState_Equals,
    .compare = (PARCObjectCompare *)strategyNexthopState_Compare,
    .hashCode = (PARCObjectHashCode *)strategyNexthopState_HashCode,
    .display = (PARCObjectDisplay *)strategyNexthopState_Display);

void strategyNexthopState_AssertValid(const StrategyNexthopState *instance) {
  parcAssertTrue(strategyNexthopState_IsValid(instance),
                 "StrategyNexthopState is not valid.");
}

StrategyNexthopState *strategyNexthopState_Create() {
  StrategyNexthopState *result =
      parcObject_CreateInstance(StrategyNexthopState);
  if (result != NULL) {
    result->pi = 0;
    result->avg_pi = 0.0;
    result->weight = 1;
  }
  return result;
}

void strategyNexthopState_Reset(StrategyNexthopState *x) {
  x->pi = 0;
  x->avg_pi = 0.0;
  x->weight = 1;
}

int strategyNexthopState_Compare(const StrategyNexthopState *val,
                                 const StrategyNexthopState *other) {
  if (val == NULL) {
    if (other != NULL) {
      return -1;
    }
  } else if (other == NULL) {
    return 1;
  } else {
    strategyNexthopState_OptionalAssertValid(val);
    strategyNexthopState_OptionalAssertValid(other);

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
  }

  return 0;
}

StrategyNexthopState *strategyNexthopState_Copy(
    const StrategyNexthopState *original) {
  StrategyNexthopState *result = strategyNexthopState_Create();
  result->pi = original->pi;
  result->avg_pi = original->avg_pi;
  result->weight = original->weight;

  return result;
}

void strategyNexthopState_Display(const StrategyNexthopState *instance,
                                  int indentation) {
  parcDisplayIndented_PrintLine(indentation, "StrategyNexthopState@%p {",
                                instance);
  parcDisplayIndented_PrintLine(indentation + 1, "%d", instance->pi);
  parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->avg_pi);
  parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->weight);
  parcDisplayIndented_PrintLine(indentation, "}");
}

bool strategyNexthopState_Equals(const StrategyNexthopState *x,
                                 const StrategyNexthopState *y) {
  bool result = false;

  if (x == y) {
    result = true;
  } else if (x == NULL || y == NULL) {
    result = false;
  } else {
    strategyNexthopState_OptionalAssertValid(x);
    strategyNexthopState_OptionalAssertValid(y);

    if (strategyNexthopState_Compare(x, y) == 0) {
      result = true;
    }
  }

  return result;
}

PARCHashCode strategyNexthopState_HashCode(const StrategyNexthopState *x) {
  PARCHashCode result = 0;
  char str[128];
  sprintf(str, "PI:%d: AVG_PI:%f: W:%f", x->pi, x->avg_pi, x->weight);
  result = parcHashCode_Hash((uint8_t *)&str, strlen(str));
  return result;
}

bool strategyNexthopState_IsValid(const StrategyNexthopState *x) {
  bool result = false;

  if (x != NULL) {
    result = true;
  }

  return result;
}

char *strategyNexthopState_ToString(const StrategyNexthopState *x) {
  // this is not implemented
  parcTrapNotImplemented("strategyNexthopState_ToString is not implemented");
  return NULL;
}

unsigned strategyNexthopState_GetPI(const StrategyNexthopState *x) {
  strategyNexthopState_OptionalAssertValid(x);

  return x->pi;
}

double strategyNexthopState_GetAvgPI(const StrategyNexthopState *x) {
  strategyNexthopState_OptionalAssertValid(x);

  return x->avg_pi;
}

double strategyNexthopState_GetWeight(const StrategyNexthopState *x) {
  strategyNexthopState_OptionalAssertValid(x);

  return x->weight;
}

double strategyNexthopState_UpdateState(StrategyNexthopState *x, bool inc,
                                        double alpha) {
  if (inc) {
    x->pi++;
  } else {
    if (x->pi > 0) {
      x->pi--;
    }
  }
  x->avg_pi = (x->avg_pi * alpha) + (x->pi * (1 - alpha));
#ifdef WITH_POLICY
  if (x->avg_pi < AVG_PI_THRESHOLD) {
#else
  if (x->avg_pi == 0.0) {
#endif /* WITH_POLICY */
    x->avg_pi = 0.1;
  }
  x->weight = 1 / x->avg_pi;

  return x->weight;
}
