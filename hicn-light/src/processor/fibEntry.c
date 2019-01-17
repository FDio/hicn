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


#include <src/config.h>
#include <stdio.h>

#include <src/processor/fibEntry.h>
#include <src/core/numberSet.h>

#include <src/core/nameBitvector.h>

#include <src/strategies/strategyImpl.h>
#include <src/strategies/rnd.h>
#include <src/strategies/loadBalancer.h>
#include <src/strategies/rndSegment.h>
#include <src/strategies/loadBalancerWithPD.h>
#ifdef WITH_MAPME
#include <src/core/ticks.h>
#include <parc/algol/parc_HashMap.h>
#endif /* WITH_MAPME */

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>

#include <src/utils/commands.h>

struct fib_entry {
    Name *name;
    unsigned refcount;
    StrategyImpl *fwdStrategy;
#ifdef WITH_MAPME
    void * userData;
    void (*userDataRelease)(void ** userData);
#endif /* WITH_MAPME */
};


FibEntry *
fibEntry_Create(Name *name, strategy_type fwdStrategy)
{
    FibEntry *fibEntry = parcMemory_AllocateAndClear(sizeof(FibEntry));
    parcAssertNotNull(fibEntry, "parcMemory_AllocateAndClear(%zu) returned NULL", sizeof(FibEntry));
    fibEntry->name = name_Acquire(name);

    if (fwdStrategy) {
        switch(fwdStrategy){
            case SET_STRATEGY_LOADBALANCER:
                fibEntry->fwdStrategy = strategyLoadBalancer_Create();
                break;

            case SET_STRATEGY_RANDOM_PER_DASH_SEGMENT:
                fibEntry->fwdStrategy = strategyRndSegment_Create();
                break;

            case SET_STRATEGY_LOADBALANCER_WITH_DELAY:
                fibEntry->fwdStrategy = strategyLoadBalancerWithPD_Create();
                break;

            default:
                //LB is the defualt strategy
                fibEntry->fwdStrategy = strategyLoadBalancer_Create();
                //the LB strategy is the default one
                //other strategies can be set using the appropiate function
                break;
        }

    } else {
        fibEntry->fwdStrategy = strategyLoadBalancer_Create();
    }

    fibEntry->refcount = 1;

#ifdef WITH_MAPME
    fibEntry->userData = NULL;
    fibEntry->userDataRelease = NULL;
#endif /* WITH_MAPME */

    return fibEntry;
}

FibEntry *
fibEntry_Acquire(const FibEntry *fibEntry)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    FibEntry *copy = (FibEntry *) fibEntry;
    copy->refcount++;
    return copy;
}

void
fibEntry_Release(FibEntry **fibEntryPtr)
{
    FibEntry *fibEntry = *fibEntryPtr;
    parcAssertTrue(fibEntry->refcount > 0, "Illegal state: refcount is 0");
    fibEntry->refcount--;
    if (fibEntry->refcount == 0) {
        name_Release(&fibEntry->name);
        fibEntry->fwdStrategy->destroy(&(fibEntry->fwdStrategy));
#ifdef WITH_MAPME
        if (fibEntry->userData) {
            fibEntry->userDataRelease(&fibEntry->userData);
        }
#endif /* WITH_MAPME */
        parcMemory_Deallocate((void **) &fibEntry);
    }
    *fibEntryPtr = NULL;
}

void
fibEntry_SetStrategy(FibEntry *fibEntry, strategy_type strategy)
{
    StrategyImpl *fwdStrategyImpl;

    switch(strategy){
        case SET_STRATEGY_LOADBALANCER:
            fwdStrategyImpl = strategyLoadBalancer_Create();
            break;

        case SET_STRATEGY_RANDOM_PER_DASH_SEGMENT:
            fwdStrategyImpl = strategyRndSegment_Create();
            break;

        case SET_STRATEGY_LOADBALANCER_WITH_DELAY:
            fwdStrategyImpl = strategyLoadBalancerWithPD_Create();
            break;

        default:
            //LB is the defualt strategy
            fwdStrategyImpl = strategyLoadBalancer_Create();
            //the LB strategy is the default one
            //other strategies can be set using the appropiate function
            break;
    }

    const NumberSet *nexthops = fibEntry_GetNexthops(fibEntry);
    unsigned size = fibEntry_NexthopCount(fibEntry);
    for (unsigned i = 0; i < size; i++) {
        fwdStrategyImpl->addNexthop(fwdStrategyImpl, numberSet_GetItem(nexthops, i));
    }
    fibEntry->fwdStrategy->destroy(&(fibEntry->fwdStrategy));
    fibEntry->fwdStrategy = fwdStrategyImpl;

}
void
fibEntry_AddNexthop(FibEntry *fibEntry, unsigned connectionId)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    fibEntry->fwdStrategy->addNexthop(fibEntry->fwdStrategy, connectionId);
}

void
fibEntry_RemoveNexthopByConnectionId(FibEntry *fibEntry, unsigned connectionId)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    fibEntry->fwdStrategy->removeNexthop(fibEntry->fwdStrategy, connectionId);
}


size_t
fibEntry_NexthopCount(const FibEntry *fibEntry)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    return fibEntry->fwdStrategy->countNexthops(fibEntry->fwdStrategy);
}

const NumberSet *
fibEntry_GetNexthops(const FibEntry *fibEntry)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    return fibEntry->fwdStrategy->returnNexthops(fibEntry->fwdStrategy);
}

const NumberSet *
fibEntry_GetNexthopsFromForwardingStrategy(const FibEntry *fibEntry,
                                                  const Message *interestMessage)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    return fibEntry->fwdStrategy->lookupNexthop(fibEntry->fwdStrategy, interestMessage);
}

void
fibEntry_ReceiveObjectMessage(const FibEntry *fibEntry,
                                     const NumberSet *egressId,
                                     const Message *objectMessage,
                                     Ticks rtt)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    fibEntry->fwdStrategy->receiveObject(fibEntry->fwdStrategy, egressId, objectMessage, rtt);
}

void
fibEntry_OnTimeout(const FibEntry *fibEntry, const NumberSet *egressId)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    fibEntry->fwdStrategy->onTimeout(fibEntry->fwdStrategy, egressId);
}

Name *
fibEntry_GetPrefix(const FibEntry *fibEntry)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    return fibEntry->name;
    //return metisName_Acquire(fibEntry->name);
}

strategy_type
fibEntry_GetFwdStrategyType(const FibEntry *fibEntry)
{
    return fibEntry->fwdStrategy->getStrategy(fibEntry->fwdStrategy);
}

StrategyImpl *
fibEntry_GetFwdStrategy(const FibEntry *fibEntry)
{
    return fibEntry->fwdStrategy;
}

#ifdef WITH_MAPME

void
fibEntry_AddNexthopByConnectionId(FibEntry *fibEntry, unsigned connectionId)
{
        parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
            fibEntry->fwdStrategy->addNexthop(fibEntry->fwdStrategy, connectionId);
}

void *
fibEntry_getUserData(const FibEntry *fibEntry)
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    return fibEntry->userData;
}

void
fibEntry_setUserData(FibEntry *fibEntry, const void * userData, void (*userDataRelease)(void**))
{
    parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
    fibEntry->userData = (void *) userData;
    fibEntry->userDataRelease = userDataRelease;
}

#endif /* WITH_MAPME */
