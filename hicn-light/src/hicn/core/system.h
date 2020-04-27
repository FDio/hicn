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
 * @header system.h
 * @abstract System-level properties
 * @discussion
 *     <#Discussion#>
 *
 */

#ifndef system_h
#define system_h

#include <hicn/core/forwarder.h>

/**
 * @function system_Interfaces
 * @abstract The system network interfaces
 */
InterfaceSet *system_Interfaces(Forwarder *forwarder);

/**
 * Returns the MTU of the named interface
 *
 * @param [in] an allocated hicn-light forwarder
 * @param [in] interfaceName The system interface name, e.g. "eth0"
 *
 * @return 0 Interface does not exist
 * @return positive the MTU the kernel reports
 *
 */
unsigned system_InterfaceMtu(Forwarder *forwarder, const char *interfaceName);

/**
 * Returns the LINK address of the specified interface
 *
 * @param [in] an allocated hicn-light forwarder
 * @param [in] interfaceName The system interface name, e.g. "eth0"
 *
 * @retval non-null The MAC address of the interface
 * @retval null The interface does not exist
 *
 */
Address *system_GetMacAddressByName(Forwarder *forwarder,
                                    const char *interfaceName);
#endif
