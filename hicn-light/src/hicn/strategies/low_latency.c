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

#if 0

#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <hicn/base/khash.h>

#include <parc/assert/parc_Assert.h>
#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_Unsigned.h>

#include <hicn/core/messageHandler.h>

#include "low_latency.h"

#define STABILITY_FACTOR 15
#define MAX_SWITCH_TRY 10
#define MAX_LATENCY_DIFF 10
#define MAX_TOLLERATED_LATENCY_DIFF 15
#define MAX_ROUNDS_MP_WITHOUT_CHECK 2
#define MAX_ROUNDS_AVOIDING_MULTIPATH 40 /* about 20 sec */
#define MAX_ROUNDS_WITH_ERROR 4
#define PROBE_LIFETIME 500 /* ms */

#define MAX_ROUNS_WITHOUT_PROBES 4

/*
 * If we do not receives probes for 4 rounds it means that we had no responce
 * from any producer for 2 sec we can say that this interface is daed
 */
#define MIN_NON_LOSSY_ROUNDS 10

/*
 * Number of rounds in non lossy mode before switch to no lossy state
 * Defaults to 10 %
 */
#define MAX_LOSS_RATE 0.10

/* Shorthands */
#define nexthop_state_t strategy_low_latency_nexthop_state_t
#define state_t strategy_low_latency_state_t

#define NEXTHOP_STATE_INIT {                    \
    .in_use = false,                            \
    .is_allowed = true,                         \
    .sent_packets = 0,                          \
    .last_try_to_switch_round = 0,              \
    .try_to_switch_counter = 0,                 \
    .recevied_probes = 0,                       \
    .rounds_without_probes = 0,                 \
    .sent_probes = 0,                           \
    .lost_probes = 0,                           \
    .non_lossy_rounds = MIN_NON_LOSSY_ROUNDS,   \
    .avg_rtt = -1.0,                            \
    .avg_rtt_in_use = -1.0,                     \
    .avg_queue = 0.0001,                        \
    .avg_loss_rate = 0.0,                       \
}

// XXX ????
#define STATE_INIT {                            \
}

static
    void
strategy_low_latency_SendProbesCB(int fd, PARCEventType which_event, void *data)
{
    parcAssertTrue(which_event & PARCEventType_Timeout,
            "Event incorrect, expecting %X set, got %X",
            PARCEventType_Timeout, which_event);

    StrategyLowLatency *ll = (StrategyLowLatency *) data;

    //delete old pending probes
    if(parcHashMap_Size(ll->pending_probes_ticks) != 0){
        Ticks now = forwarder_GetTicks(ll->forwarder);
        PARCIterator *iterator = parcHashMap_CreateKeyIterator(ll->pending_probes_ticks);
        NumberSet *to_remove = numberSet_Create();
        while(parcIterator_HasNext(iterator)) {
            PARCUnsigned *parc_seq = (PARCUnsigned *) parcIterator_Next(iterator);
            PARCUnsigned *parc_time = (PARCUnsigned *) parcHashMap_Get(ll->pending_probes_ticks, parc_seq);
            Ticks sent_time = parcUnsigned_GetUnsigned(parc_time);
            if((now - sent_time) > PROBE_LIFETIME){
                //probes to delete
                numberSet_Add(to_remove, parcUnsigned_GetUnsigned(parc_seq));
            }
        }
        parcIterator_Release(&iterator);

        for(int i = 0; i < numberSet_Length(to_remove); i++){
            PARCUnsigned *prob_seq = parcUnsigned_Create(numberSet_GetItem(to_remove,i));
            PARCUnsigned *cid = (PARCUnsigned *) parcHashMap_Get(ll->pending_probes_faces, prob_seq);
            StrategyNexthopStateLL *state =
                (StrategyNexthopStateLL *) parcHashMap_Get(ll->strategy_state, cid);
            strategyNexthopStateLL_LostProbe(state);
            parcHashMap_Remove(ll->pending_probes_ticks, prob_seq);
            parcHashMap_Remove(ll->pending_probes_faces, prob_seq);
            parcUnsigned_Release(&prob_seq);
        }
        numberSet_Release(&to_remove);
    }

    ConnectionTable * ct = forwarder_GetConnectionTable(ll->forwarder);

    PARCIterator *iterator = parcHashMap_CreateKeyIterator(ll->strategy_state);
    while(parcIterator_HasNext(iterator)){
        PARCUnsigned *cid = (PARCUnsigned *) parcIterator_Next(iterator);
        Connection *conn =
            (Connection *)connectionTable_FindById(ct,
                    parcUnsigned_GetUnsigned(cid));
        if(!conn)
            continue;

        StrategyNexthopStateLL *state =
            (StrategyNexthopStateLL *) parcHashMap_Get(ll->strategy_state, cid);

        //probe only usable paths
        if(!strategyNexthopStateLL_IsAllowed(state))
            continue;

        uint32_t seq = rand();
        messageHandler_SetProbeName(ll->probe, HF_INET6_TCP,
                ll->name, seq);
        connection_Probe(conn, ll->probe);

        PARCUnsigned *parc_seq = parcUnsigned_Create(seq);
        Ticks now = forwarder_GetTicks(ll->forwarder);
        PARCUnsigned *parc_time = parcUnsigned_Create((unsigned int)now);
        parcHashMap_Put(ll->pending_probes_ticks, parc_seq, parc_time);
        parcHashMap_Put(ll->pending_probes_faces, parc_seq, cid);
        strategyNexthopStateLL_SentProbe(state);
        parcUnsigned_Release(&parc_seq);
        parcUnsigned_Release(&parc_time);
    }
    parcIterator_Release(&iterator);

    struct timeval timeout = {0,50000};
    parcEventTimer_Start(ll->sendProbes, &timeout);
}

static
void
strategy_low_latency_SendMapmeUpdate(StrategyLowLatency *ll,
        const NumberSet * nexthops){
    MapMe * mapme = forwarder_getMapmeInstance(ll->forwarder);
    FIB * fib = forwarder_getFib((Forwarder*) ll->forwarder);
    for(unsigned i = 0; i < ll->related_prefixes_len; i++){
        FibEntry *fibEntry = fib_MatchName(fib, ll->related_prefixes[i]);
        if (!fibEntry)
            continue;
        mapme_maybe_send_updates(mapme, fibEntry, nexthops);
    }
}

static
void
strategy_low_latency_SelectBestFaces(StrategyLowLatency *ll, bool new_round)
{

    StrategyNexthopStateLL * old_faces[2];
    old_faces[0] = ll->bestFaces[0];
    old_faces[1] = ll->bestFaces[1];

    if(new_round){
        ll->round++;
    }

    if(parcHashMap_Size(ll->strategy_state) == 0){
        ll->bestFaces[0] = NULL;
        ll->bestFaces[1] = NULL;
        ll->use2paths = false;
        goto NEW_ROUND;
    }

    if(ll->use2paths && ll->bestFaces[0] != NULL && ll->bestFaces[1] != NULL){
        //multipath  case

        if(!strategyNexthopStateLL_IsLossy(ll->bestFaces[0])
                && !strategyNexthopStateLL_IsLossy(ll->bestFaces[1])
                && strategyNexthopStateLL_IsAllowed(ll->bestFaces[0])
                && strategyNexthopStateLL_IsAllowed(ll->bestFaces[1])){

            if(ll->rounds_in_multipath < MAX_ROUNDS_MP_WITHOUT_CHECK){
                //we are at the first rounds of the multipath let's wait a bit
                //(MAX_ROUNDS_MP_WITHOUT_CHECK) to make the queuing converge
                ll->rounds_in_multipath++;
                goto NEW_ROUND;
            }

            //we need to decide if we want ot keep using two paths or not
            ll->rounds_in_multipath++;
            double rtt0 = strategyNexthopStateLL_GetRTTLive(ll->bestFaces[0]);
            double rtt1 = strategyNexthopStateLL_GetRTTLive(ll->bestFaces[1]);
            double diff = fabs(rtt0 - rtt1);

            if(diff < MAX_LATENCY_DIFF){
                //everything is working, keep using the two paths
                ll->rounds_with_error = 0;
                goto NEW_ROUND;
            }

            //check for how many rounds we had problems
            if(ll->rounds_with_error < MAX_ROUNDS_WITH_ERROR &&
                    diff < MAX_TOLLERATED_LATENCY_DIFF){
                //we can tollerate few round with errors
                ll->rounds_with_error++;
                goto NEW_ROUND;
            }

            //prevent the usage of multiple paths
            ll->rounds_with_error = 0;
            ll->avoid_multipath = true;
            ll->rounds_avoiding_multipath = 0;
        } //else
        //at least one of the two path is lossy
        //or it is not allowed by the policies.
        //search for a better possibility
    }

    ll->bestFaces[0] = NULL;
    ll->bestFaces[1] = NULL;

    //check if there is at least one non lossy connection
    PARCIterator *iterator = parcHashMap_CreateKeyIterator(ll->strategy_state);
    bool check_losses = true;
    bool found_good_face = false;
    while(parcIterator_HasNext(iterator) && !found_good_face){
        PARCUnsigned *cid = (PARCUnsigned *) parcIterator_Next(iterator);
        const StrategyNexthopStateLL *state = parcHashMap_Get(ll->strategy_state, cid);
        if(!strategyNexthopStateLL_IsLossy(state) &&
                strategyNexthopStateLL_IsAllowed(state)){
            found_good_face = true;
        }
    }
    parcIterator_Release(&iterator);
    if(!found_good_face){
        // all the available faces are lossy, so we take into account only
        // the latency computed with the probes
        check_losses = false;
    }

    if(ll->bestFaces[0] == NULL){
        //try to take a random face
        PARCIterator *iterator = parcHashMap_CreateKeyIterator(ll->strategy_state);
        bool face_found = false;
        while(parcIterator_HasNext(iterator) && !face_found) {
            PARCUnsigned *cid = (PARCUnsigned *) parcIterator_Next(iterator);
            StrategyNexthopStateLL *state = (StrategyNexthopStateLL *)
                parcHashMap_Get(ll->strategy_state, cid);

            if((check_losses && strategyNexthopStateLL_IsLossy(state)) ||
                    !strategyNexthopStateLL_IsAllowed(state)){
                //skip the face
                continue;
            }

            ll->bestFaces[0] = state;
            face_found = true;
        }
        parcIterator_Release(&iterator);
    }

    if(ll->bestFaces[0] == NULL){
        //no usable face exists
        ll->bestFaces[0] = NULL;
        ll->bestFaces[1] = NULL;
        ll->use2paths = false;
        goto NEW_ROUND;
    }

    double bestRtt = strategyNexthopStateLL_GetRTTLive(ll->bestFaces[0]);

    if(ll->avoid_multipath)
        ll->rounds_avoiding_multipath++;

    if(ll->rounds_avoiding_multipath > MAX_ROUNDS_AVOIDING_MULTIPATH){
        ll->avoid_multipath = false;
        ll->rounds_avoiding_multipath = 0;
    }

    iterator = parcHashMap_CreateKeyIterator(ll->strategy_state);
    while (parcIterator_HasNext(iterator)) {

        PARCUnsigned *cid = (PARCUnsigned *) parcIterator_Next(iterator);
        StrategyNexthopStateLL *state = (StrategyNexthopStateLL *)
            parcHashMap_Get(ll->strategy_state, cid);
        double rtt = strategyNexthopStateLL_GetRTTLive(state);

        if((check_losses && strategyNexthopStateLL_IsLossy(state)) ||
                !strategyNexthopStateLL_IsAllowed(state)){
            //skip the face
            continue;
        }

        if(rtt + STABILITY_FACTOR < bestRtt){
            //maybe we found a better face
            double rttInUse = strategyNexthopStateLL_GetRTTInUse(state);
            unsigned try = strategyNexthopStateLL_GetTryToSwitch(state);

            //we check the rtt in use to check if the new face that we found
            //gets congested when we use it to send the traffic
            if(rttInUse < bestRtt || try > MAX_SWITCH_TRY){
                //we have a new best face!
                strategyNexthopStateLL_ResetTryToSwitch((StrategyNexthopStateLL*) state);
                bestRtt = rtt;
                if(ll->bestFaces[0] != NULL)
                    strategyNexthopStateLL_SetUnusedFace(ll->bestFaces[0]);
                ll->bestFaces[0] = (StrategyNexthopStateLL*) state;
            }else{
                //in this case we should switch but we wait MAX_SWITCH_TRY
                //before switch to avoid ossillations between different paths
                strategyNexthopStateLL_IncreaseTryToSwitch(
                        (StrategyNexthopStateLL*) state, ll->round);
            }
        }
    }

    parcIterator_Release(&iterator);

    if(ll->bestFaces[0] == NULL){
        //we found no face so return
        ll->bestFaces[0] = NULL;
        ll->bestFaces[1] = NULL;
        ll->use2paths = false;
        goto NEW_ROUND;
    }

    if(parcHashMap_Size(ll->strategy_state) == 1 || ll->avoid_multipath){
        //in this case (one face available or avoid multipath) we stop the
        //search here. Just reset face 1 if needed
        if(ll->bestFaces[1] != NULL){
            strategyNexthopStateLL_SetUnusedFace(ll->bestFaces[1]);
            ll->bestFaces[1] = NULL;
        }
        ll->use2paths = false;
        goto NEW_ROUND;
    }

    //if we are here we have more than 1 interface, so we search for a second one
    //to use in case of multipath
    iterator = parcHashMap_CreateKeyIterator(ll->strategy_state);
    while (parcIterator_HasNext(iterator)) {
        PARCUnsigned *cid = (PARCUnsigned *) parcIterator_Next(iterator);
        if(parcUnsigned_GetUnsigned(cid) !=
                strategyNexthopStateLL_GetFaceId(ll->bestFaces[0])){

            StrategyNexthopStateLL *state = (StrategyNexthopStateLL *)
                parcHashMap_Get(ll->strategy_state, cid);

            if((check_losses && strategyNexthopStateLL_IsLossy(state)) ||
                    !strategyNexthopStateLL_IsAllowed(state)){
                //skip the face
                continue;
            }

            if(ll->bestFaces[1] == NULL){
                //in case of 2 faces we should pass always here
                ll->bestFaces[1] = state;
            }else{
                //TODO this must be tested with more then 2 faces
                double rtt1 = strategyNexthopStateLL_GetRTTLive(ll->bestFaces[1]);
                double rttNewFace = strategyNexthopStateLL_GetRTTLive(state);
                if(rttNewFace + STABILITY_FACTOR < rtt1){
                    strategyNexthopStateLL_SetUnusedFace(ll->bestFaces[1]);
                    ll->bestFaces[1] = state;
                }
            }
        }
    }
    parcIterator_Release(&iterator);

    if(ll->bestFaces[1] != NULL){
        //we are not using the second face yet so we use the normal rtt for comparison
        double rtt0 = strategyNexthopStateLL_GetRTTProbe(ll->bestFaces[0]);
        double rtt1 = strategyNexthopStateLL_GetRTTProbe(ll->bestFaces[1]);
        double diff = fabs(rtt0 - rtt1);
        if(diff < MAX_LATENCY_DIFF) {
            //let's start to use 2 paths
            ll->rounds_with_error = 0;
            ll->use2paths = true;
            ll->rounds_in_multipath = 0;
        }else{
            //we use only one path
            strategyNexthopStateLL_SetUnusedFace(ll->bestFaces[1]);
            ll->bestFaces[1] = NULL;
            ll->use2paths = false;
        }
    }else{
        ll->use2paths = false;
    }

NEW_ROUND:
    {
        Logger * log = forwarder_GetLogger(ll->forwarder);
        if(log != NULL &&
                logger_IsLoggable(log, LoggerFacility_Strategy, PARCLogLevel_Info)){
            if(ll->use2paths){
                logger_Log(log, LoggerFacility_Strategy, PARCLogLevel_Info,
                        __func__, "use 2 paths. rtt face %d = %f queue = %f is_lossy = %d,"
                        "rtt face %d = %f queue = %f is_lossy = %d\n",
                        strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]),
                        strategyNexthopStateLL_GetRTTLive(ll->bestFaces[0]),
                        strategyNexthopStateLL_GetQueuing(ll->bestFaces[0]),
                        strategyNexthopStateLL_IsLossy(ll->bestFaces[0]),
                        strategyNexthopStateLL_GetFaceId(ll->bestFaces[1]),
                        strategyNexthopStateLL_GetRTTLive(ll->bestFaces[1]),
                        strategyNexthopStateLL_GetQueuing(ll->bestFaces[1]),
                        strategyNexthopStateLL_IsLossy(ll->bestFaces[1]));
            }else{
                if(ll->bestFaces[0] != NULL){
                    logger_Log(log, LoggerFacility_Strategy,
                            PARCLogLevel_Info, __func__,
                            "use 1 path. rtt face %d = %f is_lossy = %d, "
                            "(avoid multipath = %d)\n",
                            strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]),
                            strategyNexthopStateLL_GetRTTLive(ll->bestFaces[0]),
                            strategyNexthopStateLL_IsLossy(ll->bestFaces[0]),
                            ll->avoid_multipath);
                }else{
                    logger_Log(log, LoggerFacility_Strategy, PARCLogLevel_Info,
                            __func__, "no face to use!\n");
                }
            }
        }
    }

    //update the round only at the end for all the faces
    if(new_round){
        PARCIterator * iterator = parcHashMap_CreateKeyIterator(ll->strategy_state);
        while (parcIterator_HasNext(iterator)) {
            PARCUnsigned *cid = (PARCUnsigned *) parcIterator_Next(iterator);
            strategyNexthopStateLL_StartNewRound((StrategyNexthopStateLL *)
                    parcHashMap_Get(ll->strategy_state, cid));
        }
        parcIterator_Release(&iterator);
    }

    //mapme updates
    //if ll->bestFaces[0] == NULL we don't have any output faces
    //so don't need to send any updates since we are disconnected
    if(ll->related_prefixes_len != 0){
        if(ll->bestFaces[0] != NULL){
            NumberSet *out = numberSet_Create();
            if(old_faces[0] == NULL ||
                    (strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]) !=
                     strategyNexthopStateLL_GetFaceId(old_faces[0]))){
                //there is a new face 0 so we need a map me update
                //if ll->bestFaces[1] != NULL we need to send the update
                //even if it is the same as before
                numberSet_Add(out,
                        strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]));
                if(ll->bestFaces[1] != NULL){
                    numberSet_Add(out,
                            strategyNexthopStateLL_GetFaceId(ll->bestFaces[1]));
                }
                strategy_low_latency_SendMapmeUpdate(ll,out);
            }else{
                if(ll->bestFaces[1] != NULL){
                    if(old_faces[1] == NULL ||
                            (strategyNexthopStateLL_GetFaceId(ll->bestFaces[1]) !=
                             strategyNexthopStateLL_GetFaceId(old_faces[1]))){
                        //send a mapme both with face 0 and face 1
                        numberSet_Add(out,
                                strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]));
                        numberSet_Add(out,
                                strategyNexthopStateLL_GetFaceId(ll->bestFaces[1]));
                        strategy_low_latency_SendMapmeUpdate(ll,out);
                    }
                }else{
                    if(old_faces[1] != NULL){
                        //in the previuos round we were using two faces, now only one
                        //send update with only face 0
                        numberSet_Add(out,
                                strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]));
                        strategy_low_latency_SendMapmeUpdate(ll,out);
                    }
                }
            }
            numberSet_Release(&out);
        }
    }
}

static
void
strategy_low_latency_BestFaceCB(int fd, PARCEventType which_event, void *data)
{
    parcAssertTrue(which_event & PARCEventType_Timeout,
            "Event incorrect, expecting %X set, got %X",
            PARCEventType_Timeout, which_event);

    StrategyLowLatency * ll = (StrategyLowLatency *) data;
    strategy_low_latency_SelectBestFaces(ll, true);

    struct timeval timeout = {0, 500000};
    parcEventTimer_Start(ll->computeBestFace, &timeout);
}

static
void
_startTimers(strategy_entry_t * entry)
{
    struct timeval timeoutProbes = {0, 10000};
    struct timeval timeoutBF = {1, 0};

    parcEventTimer_Start(entry->state.sendProbes, &timeoutProbes);
    parcEventTimer_Start(entry->state.computeBestFace, &timeoutBF);
}

static
void
_stopTimers(strategy_entry_t * entry)
{
    parcEventTimer_Stop(entry->state.sendProbes);
    parcEventTimer_Stop(entry->state.computeBestFace);
}

static
void
strategy_low_latency_initialize(strategy_entry_t * entry)
{
    srand((unsigned int)time(NULL));

    /* XXX TODO Three hashmaps to initialize */
    strategy->strategy_state = parcHashMap_Create();
    strategy->pending_probes_ticks = parcHashMap_Create();
    strategy->pending_probes_faces = parcHashMap_Create();

    Dispatcher *dispatcher = forwarder_GetDispatcher((Forwarder *)ll->forwarder);
    ip_prefix_t address;
    nameBitvector_ToIPAddress(name_GetContentName(
                fibEntry_GetPrefix(fibEntry)), &address);

    entry->state = {
        .probe = messageHandler_CreateProbePacket(HF_INET6_TCP, PROBE_LIFETIME),
        .name = messageHandler_CreateProbeName(&address);
        .sendProbes = dispatcher_CreateTimer(dispatcher, false,
                strategy_low_latency_SendProbesCB, ll);
        .round = 0;
        .rounds_in_multipath = 0;
        .rounds_with_error = 0;
        .rounds_avoiding_multipath = 0;
        .use2paths = false;
        .avoid_multipath = false;
        .computeBestFace = dispatcher_CreateTimer(dispatcher, false,
                strategy_low_latency_BestFaceCB, ll);
        .related_prefixes_len = related_prefixes_len;
        // XXX TODO
        .related_prefixes = malloc(sizeof(Name *) * related_prefixes_len);
    };

    for(unsigned i = 0; i < entry->state.related_prefixes_len; i++){
        entry->state.related_prefixes[i] = name_Copy(related_prefixes[i]);
    }
}

static
void
strategy_low_latency_finalize(strategy_entry_t * entry)
{
    _stopTimers(entry);

    parcEventTimer_Destroy(&(strategy->sendProbes));
    parcEventTimer_Destroy(&(strategy->computeBestFace));

    if (parcHashMap_Size(strategy->strategy_state) > 0) {
        PARCIterator *it = parcHashMap_CreateKeyIterator(strategy->strategy_state);
        while (parcIterator_HasNext(it)) {
            PARCUnsigned *cid = parcIterator_Next(it);
            StrategyNexthopStateLL *state =
                (StrategyNexthopStateLL *)parcHashMap_Get(strategy->strategy_state, cid);
            parcObject_Release((void**)&state);
        }
        parcIterator_Release(&it);
    }

    parcHashMap_Release(&(strategy->strategy_state));
    parcHashMap_Release(&(strategy->pending_probes_ticks));
    parcHashMap_Release(&(strategy->pending_probes_faces));

    parcMemory_Deallocate(&(strategy->probe));
    parcMemory_Deallocate(&(strategy->name));

    for(unsigned i = 0; i < strategy->related_prefixes_len; i++){
        name_Release(&(strategy->related_prefixes[i]));
    }
    free(strategy->related_prefixes);

    parcMemory_Deallocate((void **)&strategy);
    parcMemory_Deallocate((void **)&impl);
    *strategyPtr = NULL;
}

static
void
strategy_low_latency_add_nexthop(strategy_entry_t * entry, unsigned nexthop, nexthop_state_t * state)
{
    PARCUnsigned *cid = parcUnsigned_Create(connectionId);

    StrategyLowLatency *ll = (StrategyLowLatency *)strategy->context;

    if (!parcHashMap_Contains(ll->strategy_state, cid)) {
        StrategyNexthopStateLL *state = strategyNexthopStateLL_Create(connectionId);
        parcHashMap_Put(ll->strategy_state, cid, state);
        if(ll->bestFaces[0] == NULL){
            ll->bestFaces[0] = state;
        }
    }

    if(parcHashMap_Size(ll->strategy_state) >= 2){
        _startTimers(strategy);
    }

    parcUnsigned_Release(&cid);
}

static
void
strategy_low_latency_remove_nexthop(strategy_entry_t * entry, unsigned nexthop, nexthop_state_t * state)
{
    bool reset_bestFaces = false;

    if((entry->state.bestFaces[0] != NULL &&
                strategyNexthopStateLL_GetFaceId(entry->state.bestFaces[0]) == connectionId) ||
            (entry->state.bestFaces[1] != NULL &&
             strategyNexthopStateLL_GetFaceId(entry->state.bestFaces[1]) == connectionId)){
        reset_bestFaces = true;
    }

    PARCUnsigned *cid = parcUnsigned_Create(connectionId);

    if (parcHashMap_Contains(entry->state.strategy_state, cid)) {
        parcHashMap_Remove(entry->state.strategy_state, cid);
    }

    if(reset_bestFaces){
        entry->state.bestFaces[0] = NULL;
        entry->state.bestFaces[1] = NULL;
        strategy_low_latency_SelectBestFaces(ll, false);
    }

    if(parcHashMap_Size(entry->state.strategy_state) < 2){
        _stopTimers(strategy);
    }

    parcUnsigned_Release(&cid);
}

static
nexthops_t *
strategy_low_latency_lookup_nexthops(strategy_entry_t * entry,
        const msgbuf_t * msgbuf)
{
    //unsigned out_connection;
    NumberSet *out = numberSet_Create();

    StrategyLowLatency *ll = (StrategyLowLatency *)strategy->context;

    //update is_allowed flag of all the next hops
    PARCIterator *iterator = parcHashMap_CreateKeyIterator(ll->strategy_state);
    while(parcIterator_HasNext(iterator)){
        PARCUnsigned *cid = (PARCUnsigned *) parcIterator_Next(iterator);
        StrategyNexthopStateLL *state =
            (StrategyNexthopStateLL *) parcHashMap_Get(ll->strategy_state, cid);
        if(numberSet_Contains(nexthops, parcUnsigned_GetUnsigned(cid))){
            strategyNexthopStateLL_SetIsAllowed(state,true);
        }else{
            strategyNexthopStateLL_SetIsAllowed(state,false);
        }
    }
    parcIterator_Release(&iterator);

    if(ll->bestFaces[0] != NULL &&
            !strategyNexthopStateLL_IsAllowed(ll->bestFaces[0])){
        //if ll->bestFaces[0] is not allowed we need to find a new face
        strategy_low_latency_SelectBestFaces(ll, false);
    }

    //at this point ll->bestFaces[0] must be allowed
    //single path case
    if(ll->bestFaces[0] != NULL && (ll->bestFaces[1] == NULL || !ll->use2paths)){
        strategyNexthopStateLL_SendPacket(ll->bestFaces[0]);
        numberSet_Add(out, strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]));

        //multipath case
    }else if(ll->bestFaces[0] != NULL && ll->bestFaces[1] != NULL && ll->use2paths){
        //it may happen that ll->bestFaces[1] is not allowed, in that case we send on
        //ll->bestFaces[0] until the next best face selection
        if(!strategyNexthopStateLL_IsAllowed(ll->bestFaces[1])){
            strategyNexthopStateLL_SendPacket(ll->bestFaces[0]);
            numberSet_Add(out, strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]));
        }else{
            double queue0 = strategyNexthopStateLL_GetQueuing(ll->bestFaces[0]);
            double queue1 = strategyNexthopStateLL_GetQueuing(ll->bestFaces[1]);
            double prob0 = 0.5;
            if(queue0 > 1 || queue1 > 1){
                prob0 = 1.0 - (queue0 / (queue0 + queue1));
            }
            double coin  = ((double) rand() / (RAND_MAX));
            if(coin < prob0){
                strategyNexthopStateLL_SendPacket(ll->bestFaces[0]);
                numberSet_Add(out, strategyNexthopStateLL_GetFaceId(ll->bestFaces[0]));
            }else{
                strategyNexthopStateLL_SendPacket(ll->bestFaces[1]);
                numberSet_Add(out, strategyNexthopStateLL_GetFaceId(ll->bestFaces[1]));
            }
        }
    }
    return out;
}



static
void
strategy_low_latency_on_data(strategy_entry_t * entry,
        const nexthops_t * nexthops, const msgbuf_t * msgbuf,
        Ticks pitEntryCreation, Ticks objReception)
{
    if (!msgbuf_is_probe(msgbuf))
        return;

    uint32_t seq = messageHandler_GetSegment(message_FixedHeader(objectMessage));
    if (!parcHashMap_Contains(ll->pending_probes_ticks, seq))
        return; // unexpected

    /* A single nexthop is expected */
    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
        const StrategyNexthopStateLL *state =
            parcHashMap_Get(ll->strategy_state, nexthop);
        if (!state)
            // this may happen if we remove a face/route while downloading a file
            // we should ignore this timeout
            continue;

        Ticks time = parcUnsigned_GetUnsigned(
                parcHashMap_Get(ll->pending_probes_ticks, seq));
        Ticks now = forwarder_GetTicks(ll->forwarder);
        Ticks RTT =  now - time;
        if(RTT <= 0)
            RTT = 1;
        strategyNexthopStateLL_AddRttSample(
                (StrategyNexthopStateLL *) state, (unsigned int)RTT);
        parcHashMap_Remove(ll->pending_probes_ticks, seq);
    }
    };
}

static
void
strategy_low_latency_on_timeout(strategy_entry_t * entry, const nexthops_t * nexthops)
{
    /* Nothing to do */
}

DECLARE_STRATEGY(low_latency);

#undef nexthop_state_t
#undef state_t

#endif
