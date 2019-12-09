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

/**
 * @file listenerSet.h
 * @brief A listener set is unique on (EncapType, localAddress)
 *
 * Keeps track of all the running listeners.  The set is unique on the
 * encapsulation type and the local address.  For example, with TCP
 * encapsulation and local address 127.0.0.1 or Ethernet encapsulation and MAC
 * address 00:11:22:33:44:55.
 *
 * NOTE: This does not allow multiple EtherType on the same interface because
 * the Address for a LINK address does not include an EtherType.
 *
 */

#ifndef listenerSet_h
#define listenerSet_h

#include <hicn/io/listener.h>

struct listener_set;
typedef struct listener_set ListenerSet;

/**
 * <#One Line Description#>
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
ListenerSet *listenerSet_Create(void);

/**
 * <#One Line Description#>
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void listenerSet_Destroy(ListenerSet **setPtr);

/**
 * @function listenerSet_Add
 * @abstract Adds the listener to the set
 * @discussion
 *     Unique set based on pair (EncapType, localAddress).
 *     Takes ownership of the ops memory if added.
 *
 * @param <#param1#>
 * @return true if added, false if not
 */
bool listenerSet_Add(ListenerSet *set, ListenerOps *ops);

/**
 * The number of listeners in the set
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] set An allocated listener set
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
size_t listenerSet_Length(const ListenerSet *set);
size_t listenerSet_Length(const ListenerSet *set);

/**
 * Returns the listener at the given index
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] set An allocated listener set
 * @param [in] index The index position (0 <= index < listenerSet_Lenght)
 *
 * @retval non-null The listener at index
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
ListenerOps *listenerSet_Get(const ListenerSet *set, size_t index);

/**
 * Looks up a listener by its key (EncapType, LocalAddress)
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] set An allocated listener set
 * @param [in] encapType the listener type
 * @param [in] localAddress The local bind address (e.g. MAC address or TCP
 * socket)
 *
 * @retval non-null The listener matching the query
 * @retval null Does not exist
 *
 * Example:
 * @code
 *
 * @endcode
 */
ListenerOps *listenerSet_Find(const ListenerSet *set, EncapType encapType,
                              const address_t *localAddress);

/**
 * Looks up a listener by its id
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] set An allocated listener set
 * @param [in] id of the listener
 *
 * @retval non-null The listener matching the query
 * @retval null Does not exist
 *
 * Example:
 * @code
 *
 * @endcode
 */
ListenerOps *listenerSet_FindById(const ListenerSet *set, unsigned id);

/**
 * Looks up a listener by its id
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] set An allocated listener set
 * @param [in] name of the listener
 *
 * @retval greater or equal to 0 The listener matching the query
 * @retval -1 Does not exist
 *
 * Example:
 * @code
 *
 * @endcode
 */
int listenerSet_FindIdByListenerName(const ListenerSet *set, const char *listenerName);

/**
 * Remove up a listener by its id
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] set An allocated listener set
 * @param [in] id of the listener
 *
 * Example:
 * @code
 *
 * @endcode
 */
void listenerSet_RemoveById(const ListenerSet *set, unsigned id);
#endif
