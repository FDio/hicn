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
    return 0.0;

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

void strategyNexthopStateLL_SentProbe(StrategyNexthopStateLL *x){
  x->sent_probes++;
}

void strategyNexthopStateLL_LostProbe(StrategyNexthopStateLL *x){
  x->lost_probes++;
}

bool strategyNexthopStateLL_IsLossy(const StrategyNexthopStateLL *x){
  if(x->non_lossy_rounds < 10 ||
     x->avg_loss_rate > MAX_LOSS_RATE){
    return true;
  }
  return false;
}

void strategyNexthopStateLL_SetIsAllowed(StrategyNexthopStateLL *x, bool allowed){
  x->is_allowed = allowed;
}

bool strategyNexthopStateLL_IsAllowed(const StrategyNexthopStateLL *x){
  return x->is_allowed;
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

  //compute losses in this round
  if(x->sent_probes != 0){
    double loss_rate = (double) x->lost_probes / (double) x->sent_probes;
    x->avg_loss_rate = x->avg_loss_rate * 0.7 + loss_rate * 0.3;
    if(x->avg_loss_rate > MAX_LOSS_RATE){
      x->non_lossy_rounds = 0;
    }else{
      x->non_lossy_rounds++;
    }
  }

  x->lost_probes = 0;
  x->sent_probes = 0;
}
