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
 * @file listener.h
 * @brief Provides the function abstraction of all Listeners.
 *
 * A listener accepts in coming packets.  A Stream listener will accept the
 * connection then pass it off to the {@link StreamConnection} class.  A
 * datagram listener will have to have its own way to multiplex packets.
 *
 */

#ifndef listener_h
#define listener_h

#include <hicn/base/address.h>
#include <hicn/base/address_pair.h>
#include <hicn/core/connection.h>

struct listener_ops;
typedef struct listener_ops ListenerOps;

typedef enum {
  ENCAP_TCP,   /**< TCP encapsulation type */
  ENCAP_UDP,   /**< UDP encapsulation type */
  ENCAP_ETHER, /**< Ethernet encapsulation type */
  ENCAP_LOCAL, /**< A connection to a local protocol stack */
  ENCAP_HICN
} EncapType;

struct listener_ops {
  /**
   * A user-defined parameter
   */
  void *context;

  /**
   * Called to destroy the Listener.
   *
   * @param [in] listenerOpsPtr Double pointer to this structure
   */
  void (*destroy)(ListenerOps **listenerOpsPtr);

  /**
   * Returns the listener name of the listener.
   *
   * @param [in] ops Pointer to this structure
   *
   * @return the listener name of the listener
   */
  const char *(*getListenerName)(const ListenerOps *ops);

  /**
   * Returns the interface index of the listener.
   *
   * @param [in] ops Pointer to this structure
   *
   * @return the interface index of the listener
   */
  unsigned (*getInterfaceIndex)(const ListenerOps *ops);

  /**
   * Returns the address pair that defines the listener (local, remote)
   *
   * @param [in] ops Pointer to this structure
   *
   * @return the (local, remote) pair of addresses
   */
  const address_t *(*getListenAddress)(const ListenerOps *ops);

  /**
   * Returns the encapsulation type of the listener (e.g. TCP, UDP, HICN)
   *
   * @param [in] ops Pointer to this structure
   *
   * @return the listener encapsulation type
   */
  EncapType (*getEncapType)(const ListenerOps *ops);

  /**
   * Returns the interface name of the listener.
   *
   * @param [in] ops Pointer to this structure
   *
   * @return the interface name of the listener
   */
  const char *(*getInterfaceName)(const ListenerOps *ops);

  /**
   * Returns the underlying socket associated with the listener
   *
   * Not all listeners are capable of returning a useful socket.  In those
   * cases, this function pointer is NULL.
   *
   * TCP does not support this operation (function is NULL).  UDP returns its
   * local socket.
   *
   * The caller should never close this socket, the listener will do that when
   * its destroy method is called.
   *
   * @param [in] ops Pointer to this structure
   *
   * @retval integer The socket descriptor
   *
   * Example:
   * @code
   * <#example#>
   * @endcode
   */
  int (*getSocket)(const ListenerOps *ops, const address_pair_t * pair);

  unsigned (*createConnection)(ListenerOps *listener, int fd, const address_pair_t * pair);
};
#endif  // listener_h
