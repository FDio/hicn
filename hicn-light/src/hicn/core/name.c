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

#include <assert.h>
#include <limits.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <hicn/common.h> // cumulative_hash32
#include <hicn/core/messageHandler.h>
#include <hicn/core/name.h>

#define IPv6_TYPE 6
#define IPv4_TYPE 4

// assumption: the IPv6 address is the name, the TCP segment number is the ICN
// segment

struct name {
    NameBitvector *content_name;
    uint32_t segment;
    uint32_t name_hash;
    // the refcount is shared between all copies
    unsigned *refCountPtr;
};

// =====================================================

static
unsigned
_getRefCount(const Name *name)
{
    return *name->refCountPtr;
}

static
void
_incrementRefCount(Name *name) {
    assert(*name->refCountPtr > 0);
    (*name->refCountPtr)++;
}

static
void
_decrementRefCount(Name *name) {
    assert(*name->refCountPtr > 0);
    (*name->refCountPtr)--;
}

static uint32_t _computeHash(Name *name) {
    assert(name);

    uint32_t hash1 = nameBitvector_GetHash32(name->content_name);
    return cumulative_hash32(&name->segment, 4, hash1);
}

// ============================================================================

Name *
name_CreateFromPacket(const uint8_t *packet, MessagePacketType type)
{
    Name *name = malloc(sizeof(Name));
    assert(name); // XXX TODO error handling

    if (messageHandler_GetIPPacketType(packet) == IPv6_TYPE) {
        if (type == MESSAGE_TYPE_INTEREST) {
            name->content_name = nameBitvector_CreateFromIn6Addr(
                    (struct in6_addr *)messageHandler_GetDestination(packet), 128);
        } else if (type == MESSAGE_TYPE_DATA) {
            name->content_name = nameBitvector_CreateFromIn6Addr(
                    (struct in6_addr *)messageHandler_GetSource(packet), 128);
        } else {
            free(name);
            return NULL;
        }
    } else if (messageHandler_GetIPPacketType(packet) == IPv4_TYPE) {
        if (type == MESSAGE_TYPE_INTEREST) {
            name->content_name = nameBitvector_CreateFromInAddr(
                    *((uint32_t *)messageHandler_GetDestination(packet)), 32);
        } else if (type == MESSAGE_TYPE_DATA) {
            name->content_name = nameBitvector_CreateFromInAddr(
                    *((uint32_t *)messageHandler_GetSource(packet)), 32);
        } else {
            free(name);
            return NULL;
        }
    } else {
        printf("Error: unknown message type\n");
        free(name);
        return NULL;
    }

    name->segment = messageHandler_GetSegment(packet);
    name->name_hash = _computeHash(name);

    name->refCountPtr = malloc(sizeof(unsigned));
    assert(name->refCountPtr); // XXX TODO error handling
    *name->refCountPtr = 1;
    return name;
}

Name *
name_CreateFromAddress(int family, ip_address_t addr,
        uint8_t len)
{
    Name *name = malloc(sizeof(Name));
    assert(name); // XXX TODO error handling

    switch(family) {
        case AF_INET:
            name->content_name = nameBitvector_CreateFromInAddr(addr.v4.as_u32, len);
            break;
        case AF_INET6:
            name->content_name = nameBitvector_CreateFromIn6Addr(&addr.v6.as_in6addr, len);
            break;
        default:
            return NULL;
    }

    name->segment = 0;
    name->name_hash = _computeHash(name);

    name->refCountPtr = malloc(sizeof(unsigned));
    assert(name->refCountPtr); // XXX TODO error handling
    *name->refCountPtr = 1;

    return name;
}

void
name_Release(Name **namePtr)
{
    assert(namePtr);
    assert(*namePtr);

    Name *name = *namePtr;
    _decrementRefCount(name);
    if (_getRefCount(name) == 0) {
        free(name->refCountPtr);
        nameBitvector_Destroy(&(name->content_name));
    }
    free(name);
    *namePtr = NULL;
}

Name *
name_Acquire(const Name *original)
{
    assert(original);

    Name *copy = malloc(sizeof(Name));
    assert(copy); // XXX TODO error handling

    memcpy(copy, original, sizeof(Name));
    _incrementRefCount(copy);

    return copy;
}

Name *
name_Copy(const Name *original)
{
    assert(original);

    Name *copy = malloc(sizeof(Name));
    assert(copy); // XXX TODO error handling

    copy->content_name = nameBitvector_Copy(original->content_name);
    copy->segment = original->segment;
    copy->name_hash = original->name_hash;

    copy->refCountPtr = malloc(sizeof(unsigned));
    assert(copy->refCountPtr); // XXX TODO error handling
    *copy->refCountPtr = 1;

    return copy;
}

uint32_t
name_HashCode(const Name *name)
{
    assert(name);
    return name->name_hash;
}

NameBitvector *
name_GetContentName(const Name *name)
{
    assert(name);
    return name->content_name;
}

bool
name_Equals(const Name *a, const Name *b)
{
    assert(a);
    assert(b);

    /* BEGIN: Workaround for HICN-400 */
    if ((!a->content_name) || (!b->content_name))
        return false;
    /* END: Workaround for HICN-400 */

    if ((nameBitvector_Equals(a->content_name, b->content_name) &&
                a->segment == b->segment))
        return true;
    return false;
}

int
name_Compare(const Name *a, const Name *b)
{
    assert(a);
    assert(b);

    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return -1;
    }
    if (b == NULL) {
        return +1;
    }

    int res = nameBitvector_Compare(a->content_name, b->content_name);

    if (res != 0) {
        return res;
    } else {
        if (a->segment < b->segment) {
            return -1;
        } else if (a->segment > b->segment) {
            return +1;
        } else {
            return 0;
        }
    }
}

char *
name_ToString(const Name *name)
{
    char *output = malloc(128);

    address_t address;
    nameBitvector_ToAddress(name_GetContentName(name), &address);

    // XXX TODO
#if 0
    sprintf(output, "name: %s seq: %u", addressToString(address),
            name->segment);
#else
    snprintf(output, 128, "%s", "Not implemented");
#endif

    return output;
}

void
name_setLen(Name *name, uint8_t len)
{
    nameBitvector_setLen(name->content_name, len);
    name->name_hash = _computeHash(name);
}

#ifdef WITH_POLICY
uint32_t
name_GetSuffix(const Name * name)
{
    return name->segment;
}

uint8_t
name_GetLen(const Name * name)
{
    return nameBitvector_GetLength(name->content_name);
}
#endif /* WITH_POLICY */
