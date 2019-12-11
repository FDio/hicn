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
#include <float.h>

#include <parc/algol/parc_DisplayIndented.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>

#include <parc/assert/parc_Assert.h>
#include <hicn/strategies/nexthopStateLowLatency.h>

const unsigned MAX_ROUNS_WITHOUT_PROBES = 4;
        //if we do not receives probes for 4 rounds it means
        //that we had no responce from any producer for 2 sec
        //we can say that this interface is daed

struct strategy_nexthop_state_ll {
  unsigned face_id;
  bool in_use;
  double avg_rtt;
  double avg_rtt_in_use;
  double avg_queue;
  unsigned sent_packets;
  unsigned last_try_to_switch_round;
  unsigned try_to_switch_counter;
  unsigned recevied_probes;
  unsigned rounds_without_probes;
};

static bool _strategyNexthopStateLL_Destructor(
    StrategyNexthopStateLL **instancePtr) {
  return true;
}

parcObject_ImplementAcquire(strategyNexthopStateLL, StrategyNexthopStateLL);

parcObject_ImplementRelease(strategyNexthopStateLL, StrategyNexthopStateLL);

parcObject_Override(
    StrategyNexthopStateLL, PARCObject,
    .destructor = (PARCObjectDestructor *)_strategyNexthopStateLL_Destructor,
    .copy = (PARCObjectCopy *)strategyNexthopStateLL_Copy,
    .display = (PARCObjectDisplay *)strategyNexthopStateLL_Display,
    .toString = (PARCObjectToString *)strategyNexthopStateLL_ToString,
    .equals = (PARCObjectEquals *)strategyNexthopStateLL_Equals,
    .compare = (PARCObjectCompare *)strategyNexthopStateLL_Compare,
    .hashCode = (PARCObjectHashCode *)strategyNexthopStateLL_HashCode,
    .display = (PARCObjectDisplay *)strategyNexthopStateLL_Display);

void strategyNexthopStateLL_AssertValid(const StrategyNexthopStateLL *instance) {
  parcAssertTrue(strategyNexthopStateLL_IsValid(instance),
                 "StrategyNexthopState is not valid.");
}

StrategyNexthopStateLL *strategyNexthopStateLL_Create(unsigned face_id) {
  StrategyNexthopStateLL *result =
      parcObject_CreateInstance(StrategyNexthopStateLL);
  if (result != NULL) {
    result->face_id = face_id;
    result->in_use = false;
    result->avg_rtt = -1.0;
    result->avg_rtt_in_use = -1.0;
    result->avg_queue = 0.0001;
    result->sent_packets = 0;
    result->last_try_to_switch_round = 0;
    result->try_to_switch_counter = 0;
    result->recevied_probes = 0;
    result->rounds_without_probes = 0;
  }
  return result;
}

void strategyNexthopStateLL_Reset(StrategyNexthopStateLL *x) {
  x->in_use = false;
  x->avg_rtt = -1.0;
  x->avg_rtt_in_use = -1.0;
  x->avg_queue = 0.0001;
  x->sent_packets = 0;
  x->last_try_to_switch_round = 0;
  x->try_to_switch_counter = 0;
  x->recevied_probes = 0;
  x->rounds_without_probes = 0;
}

int strategyNexthopStateLL_Compare(const StrategyNexthopStateLL *val,
                                 const StrategyNexthopStateLL *other) {
  if (val == NULL) {
    if (other != NULL) {
      return -1;
    }
  } else if (other == NULL) {
    return 1;
  } else {
    strategyNexthopStateLL_OptionalAssertValid(val);
    strategyNexthopStateLL_OptionalAssertValid(other);

    if (val->face_id < other->face_id) {
      return -1;
    } else if (val->face_id > other->face_id) {
      return 1;
    }

    if (val->avg_rtt < other->avg_rtt) {
      return -1;
    } else if (val->avg_rtt > other->avg_rtt) {
      return 1;
    }

    if (val->avg_rtt_in_use < other->avg_rtt_in_use) {
      return -1;
    } else if (val->avg_rtt_in_use > other->avg_rtt_in_use) {
      return 1;
    }

    if (val->avg_queue < other->avg_queue) {
      return -1;
    } else if (val->avg_queue > other->avg_queue) {
      return 1;
    }

    if (val->sent_packets < other->sent_packets) {
      return -1;
    } else if (val->sent_packets > other->sent_packets) {
      return 1;
    }

    if (val->last_try_to_switch_round < other->last_try_to_switch_round) {
      return -1;
    } else if (val->last_try_to_switch_round > other->last_try_to_switch_round) {
      return 1;
    }

    if (val->try_to_switch_counter < other->try_to_switch_counter) {
      return -1;
    } else if (val->try_to_switch_counter > other->try_to_switch_counter) {
      return 1;
    }

    if (val->recevied_probes < other->recevied_probes) {
      return -1;
    } else if (val->recevied_probes > other->recevied_probes) {
      return 1;
    }

    if (val->rounds_without_probes < other->rounds_without_probes) {
      return -1;
    } else if (val->rounds_without_probes > other->rounds_without_probes) {
      return 1;
    }

  }

  return 0;
}

StrategyNexthopStateLL *strategyNexthopStateLL_Copy(
    const StrategyNexthopStateLL *original) {
  StrategyNexthopStateLL *result = strategyNexthopStateLL_Create(original->face_id);
  result->avg_rtt = original->avg_rtt;
  result->avg_rtt_in_use = original->avg_rtt_in_use;
  result->avg_queue = original->avg_queue;
  result->sent_packets = original->sent_packets;
  result->last_try_to_switch_round = original->last_try_to_switch_round;
  result->try_to_switch_counter = original->try_to_switch_counter;
  result->recevied_probes = original->recevied_probes;
  result->rounds_without_probes = original->rounds_without_probes;
  return result;
}

void strategyNexthopStateLL_Display(const StrategyNexthopStateLL *instance,
                                  int indentation) {
  parcDisplayIndented_PrintLine(indentation, "StrategyNexthopStateLL@%p {",
                                instance);
  parcDisplayIndented_PrintLine(indentation + 1, "%d", instance->face_id);
  parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->avg_rtt);
  parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->avg_rtt_in_use);
  parcDisplayIndented_PrintLine(indentation + 1, "%f", instance->avg_queue);
  parcDisplayIndented_PrintLine(indentation, "}");
}

bool strategyNexthopStateLL_Equals(const StrategyNexthopStateLL *x,
                                 const StrategyNexthopStateLL *y) {
  bool result = false;

  if (x == y) {
    result = true;
  } else if (x == NULL || y == NULL) {
    result = false;
  } else {
    strategyNexthopStateLL_OptionalAssertValid(x);
    strategyNexthopStateLL_OptionalAssertValid(y);

    if (strategyNexthopStateLL_Compare(x, y) == 0) {
      result = true;
    }
  }

  return result;
}

PARCHashCode strategyNexthopStateLL_HashCode(const StrategyNexthopStateLL *x) {
  PARCHashCode result = 0;
  char str[128];
  sprintf(str, "ID:%d: RTT:%f: RTTUSE:%f: Q:%f", x->face_id, x->avg_rtt,
                                        x->avg_rtt_in_use, x->avg_queue);
  result = parcHashCode_Hash((uint8_t *)&str, strlen(str));
  return result;
}

bool strategyNexthopStateLL_IsValid(const StrategyNexthopStateLL *x) {
  bool result = false;

  if (x != NULL) {
    result = true;
  }

  return result;
}

char *strategyNexthopStateLL_ToString(const StrategyNexthopStateLL *x) {
  // this is not implemented
  parcTrapNotImplemented("strategyNexthopStateLL_ToString is not implemented");
  return NULL;
}

double strategyNexthopStateLL_GetRTTProbe(StrategyNexthopStateLL *x) {
  strategyNexthopStateLL_OptionalAssertValid(x);

  if(x->rounds_without_probes > MAX_ROUNS_WITHOUT_PROBES)
    return DBL_MAX;

  if(x->avg_rtt == -1.0){
    if(x->avg_rtt_in_use == -1.0){
      return 0.0;
    }else{
      //this happens if the face recevied probes only in in_use mode
      //we set the avf_rtt with rtt_in_use
      x->avg_rtt = x->avg_rtt_in_use;
    }
  }

  return x->avg_rtt;
}

double strategyNexthopStateLL_GetRTTInUse(StrategyNexthopStateLL *x) {
  strategyNexthopStateLL_OptionalAssertValid(x);

  if(x->rounds_without_probes > MAX_ROUNS_WITHOUT_PROBES)
    return DBL_MAX;

  if(x->avg_rtt_in_use == -1.0)
    return strategyNexthopStateLL_GetRTTProbe(x);

  return x->avg_rtt_in_use;
}

double strategyNexthopStateLL_GetRTTLive(StrategyNexthopStateLL *x) {
  strategyNexthopStateLL_OptionalAssertValid(x);

  if(x->in_use){
    return strategyNexthopStateLL_GetRTTInUse(x);
  }else{
    return strategyNexthopStateLL_GetRTTProbe(x);
  }
}

double strategyNexthopStateLL_GetQueuing(const StrategyNexthopStateLL *x) {
  strategyNexthopStateLL_OptionalAssertValid(x);

  if(x->rounds_without_probes > MAX_ROUNS_WITHOUT_PROBES)
    return DBL_MAX;

  return x->avg_queue;
}

void strategyNexthopStateLL_AddRttSample(StrategyNexthopStateLL *x,
                                                unsigned int rtt){
  strategyNexthopStateLL_OptionalAssertValid(x);

  x->recevied_probes++;
  //form uint to double
  double drtt = rtt;

  if(x->in_use){
    if(x->avg_rtt_in_use == -1.0){
      x->avg_rtt_in_use = drtt;
    }else{
      x->avg_rtt_in_use = (x->avg_rtt_in_use * 0.9) + (drtt * 0.1);
    }
  }else{
    if(x->avg_rtt == -1.0){
       x->avg_rtt = drtt;
    }else{
      x->avg_rtt = (x->avg_rtt * 0.9) + (drtt * 0.1);
    }
  }

  if(x->avg_rtt_in_use == -1.0 || x->avg_rtt == -1.0){
    x->avg_queue = 0.0001;
  }else{
    double queue = x->avg_rtt_in_use - x->avg_rtt;
    if(queue < 0){
      queue = 0.0001;
    }
    x->avg_queue = (x->avg_queue * 0.95) + (0.05 * queue);
  }
}

void strategyNexthopStateLL_SetUnusedFace(StrategyNexthopStateLL *x){
  strategyNexthopStateLL_OptionalAssertValid(x);
  x->in_use = false;
}

unsigned strategyNexthopStateLL_GetFaceId(StrategyNexthopStateLL *x) {
  strategyNexthopStateLL_OptionalAssertValid(x);
  return x->face_id;
}

void strategyNexthopStateLL_IncreaseTryToSwitch(StrategyNexthopStateLL *x,
                                                      unsigned round){
  if(x->try_to_switch_counter == 0 ||
        round == (x->last_try_to_switch_round + 1)){
    x->last_try_to_switch_round = round;
    x->try_to_switch_counter++;
  }else{
    x->try_to_switch_counter = 0;
  }
}

unsigned strategyNexthopStateLL_GetTryToSwitch(const StrategyNexthopStateLL *x){
  return x->try_to_switch_counter;
}

void strategyNexthopStateLL_ResetTryToSwitch(StrategyNexthopStateLL *x){
  x->try_to_switch_counter = 0;
}

void strategyNexthopStateLL_SendPacket(StrategyNexthopStateLL *x){
 x->in_use = true;
  x->sent_packets++;
}

void strategyNexthopStateLL_StartNewRound(StrategyNexthopStateLL *x){
  strategyNexthopStateLL_OptionalAssertValid(x);
  if(x->sent_packets == 0) //the face was not used in the last round
    x->in_use = false;

  x->sent_packets = 0;

  if(x->recevied_probes == 0){
    x->rounds_without_probes++;
  }else{
    x->rounds_without_probes = 0;
  }

  x->recevied_probes = 0;
}
