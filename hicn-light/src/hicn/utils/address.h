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
 * @brief Represents an endpoint address.
 *
 * Represents an endpoint address.  May be INET, INET6, or a multi-byte LINK,
 * or an Interface Index.
 *
 * INET and INET6 must contain the .sa_addr member, and other members as needed
 * by the use of the address.
 *
 * The Interface Index address is essentially a pointer to a device.
 *
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
#ifndef address_h
#define address_h

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/un.h>
#endif
#include <stdbool.h>

#include <parc/algol/parc_Buffer.h>
#include <parc/algol/parc_BufferComposer.h>
#include <hicn/utils/commands.h>

/**
 * Return a string representation of the given `address_type`
 *
 * @param [in] type A valid address_type value.
 *
 * @return NULL An error occurred
 * @return non-NULL A pointer to a static string representation of the
 * `address_type`.
 *
 * Example:
 * @code
 * {
 *     const char *typeAsString = addressTypeToString(commandAddrType_INET);
 * }
 * @endcode
 *
 * @see addressStringToType
 */
const char *addressTypeToString(address_type type);

/**
 * Return a `address_type` from the given nul-terminated C string.
 *
 * @param [in] typeAsString A nul-terminated, C string representation of a
 * `address_type`.
 *
 * @return A address_type
 *
 * Example:
 * @code
 * {
 *     address_type type = addressTypeToString("INET");
 * }
 * @endcode
 *
 * @see addressTypeToString
 */
address_type addressStringToType(const char *typeAsString);

struct address;
typedef struct address Address;

/**
 * Create a new `Address` instance from an IPv4 IP address, the port is
 * optional.
 *
 * The sockaddr_in should be filled in network byte order. The newly created
 * instance must eventually be destroyed by calling {@link addressDestroy}().
 *
 * @param [in] addr_in The `sockaddr_in` representing the IPv4 IP address with
 * which to initialize the new `Address` instance.
 * @return A new instance of `Address` that must eventually be destroyed by
 * calling {@link addressDestroy}().
 *
 * Example:
 * @code
 * {
 *     Address *dest = addressCreateFromInet(
 *                                                  &(struct sockaddr_in) {
 *                                                      .sa_addr =
 * inet_addr("foo.bar.com"), .sa_port = htons(9695) } ); addressDestroy(&dest);
 * }
 * @endcode
 * @see addressDestroy
 */
Address *addressCreateFromInet(struct sockaddr_in *addr_in);

/**
 * Create a new `Address` instance from an IPv6 IP address, the port is
 * optional.
 *
 *
 * The sockaddr_in should be filled in network byte order. The newly created
 * instance must eventually be destroyed by calling {@link addressDestroy}().
 *
 * @param [in] addr_in6 A `sockaddr_in6` from which to initialize a new instance
 * of Address
 * @return A new instance of `Address` that must eventually be destroyed by
 * calling {@link addressDestroy}()
 *
 * Example:
 * @code
 * {
 *     struct sockaddr_in6 addr_in6;
 *     memset(&addr_in6, 0, sizeof(struct sockaddr_in6));
 *
 *     inet_pton(AF_INET6, "2001:720:1500:1::a100", &(addr_in6.sin6_addr));
 *     addr_in6.sin6_family = AF_INET6;
 *     addr_in6.sin6_port = 0x0A0B;
 *     addr_in6.sin6_flowinfo = 0x01020304;
 *
 *     Address *address = addressCreateFromInet6(&addr_in6);
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 * @see addressDestroy
 */
Address *addressCreateFromInet6(struct sockaddr_in6 *addr_in6);

/**
 * Convert an internet address family (IPv4) to the address format used by the
 * Fwd.
 *
 * @param [in] addr4    IPV4 address in *Network byte order*
 * @param [in] port     Port number in *Network byte order*
 *
 * @return  A new instance of `Address` that must eventually be destroyed by
 * calling {@link addressDestroy}()
 */
Address *addressFromInaddr4Port(in_addr_t *addr4, in_port_t *port);

/**
 * Convert an internet address family (IPv6) to the address format used by the
 * Fwd
 *
 * @param [in] addr6    IPV4 address in *Network byte order*
 * @param [in] port     Port number in *Network byte order*
 *
 * @return  A new instance of `Address` that must eventually be destroyed by
 * calling {@link addressDestroy}()
 */
Address *addressFromInaddr6Port(struct in6_addr *addr6, in_port_t *port);

/**
 * Create a new `Address` instance, initialized from a Link address.
 *
 * User must know the link address format (i.e. token ring vs ethernet) and have
 * the address in a byte array. The array is encoded in left-to-right order. The
 * newly created instance must eventually be destroyed by calling {@link
 * addressDestroy}().
 *
 * @param [in] linkaddr A byte array containing the link address
 * @param [in] length The length of the link address byte array
 * @return A new instance of `Address` that must eventually be destroyed by
 * calling {@link addressDestroy}()
 *
 * Example:
 * @code
 * {
 *     uint8_t mac[] = { 0x14, 0x10, 0x9f, 0xd7, 0x0b, 0x89 };
 *     Address *address = addressCreateFromLink(mac, sizeof(mac));
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 * @see addressDestroy
 */
Address *addressCreateFromLink(const uint8_t *linkaddr, size_t length);

/**
 * Create a new `Address` instance from a network interface index.
 *
 * The interfaceIndex should be in host byte order. The newly created instance
 * must eventually be destroyed by calling {@link addressDestroy}().
 *
 * @param [in] interfaceIndex The index of the interface to encode
 * @return A new instance of `Address` that must eventually be destroyed by
 * calling {@link addressDestroy}()
 *
 * Example:
 * @code
 * {
 *     Address *address = addressCreateFromInterface(2);
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 * @see addressDestroy
 */
Address *addressCreateFromInterface(uint32_t interfaceIndex);

/**
 * Create a new Address instance from a PF_UNIX address domain.
 *
 * The newly created instance must eventually be destroyed by calling {@link
 * addressDestroy}().
 *
 * @param [in] addr_un The `struct sockaddr_un` specifying the local PF_UNIX
 * socket address
 * @return A new instance of `Address` that must eventually be destroyed by
 * calling {@link addressDestroy}()
 *
 * Example:
 * @code
 * {
 *     struct sockaddr_un addr_unix;
 *     memset(&addr_unix, 0, sizeof(struct sockaddr_un));
 *     char path[] = "/Hello/Cruel/World";
 *     strcpy(addr_un.sun_path, path);
 *     addr_un.sun_family = AF_UNIX;
 *
 *     Address *address = addressCreateFromUnix(&addr_un);
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 * @see addressDestroy
 */
Address *addressCreateFromUnix(struct sockaddr_un *addr_un);

/**
 * Create a deep copy of an instance of a `Address`. A completely new,
 * indedependent instance is created.
 *
 * The newly created instance must eventually be destroyed by calling {@link
 * addressDestroy}().
 *
 * @param [in] original A pointer to a `Address` instance to be copied.
 * @return A new instance of a Address, deep copied from the `original`
 * instance.
 *
 * Example:
 * @code
 * {
 *     Address *address = addressCreateFromInterface(2);
 *
 *     Address *copy = addressCopy(address);
 *
 *     addressDestroy(&address);
 *     addressDestroy(&copy);
 * }
 * @endcode
 * @see addressDestroy
 */
Address *addressCopy(const Address *original);

/**
 * Deallocate an instance of a Address.
 *
 * The Address instance is deallocated, and any referenced data is also
 * deallocated. The referenced pointer is set to NULL upon return.
 *
 * @param [in] addressPtr A pointer to a pointer to an instance of Address.
 *
 * Example:
 * @code
 * {
 *     Address *address = addressCreateFromInterface(2);
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 */
void addressDestroy(Address **addressPtr);

/**
 * Determine if two Address instances are equal.
 *
 *
 * The following equivalence relations on non-null `Address` instances are
 * maintained:
 *
 *  * It is reflexive: for any non-null reference value x, `addressEquals(x, x)`
 *      must return true.
 *
 *  * It is symmetric: for any non-null reference values x and y,
 *    `addressEquals(x, y)` must return true if and only if
 *        `addressEquals(y, x)` returns true.
 *
 *  * It is transitive: for any non-null reference values x, y, and z, if
 *        `addressEquals(x, y)` returns true and
 *        `addressEquals(y, z)` returns true,
 *        then  `addressEquals(x, z)` must return true.
 *
 *  * It is consistent: for any non-null reference values x and y, multiple
 *      invocations of `addressEquals(x, y)` consistently return true or
 *      consistently return false.
 *
 *  * For any non-null reference value x, `addressEquals(x, NULL)` must
 *      return false.
 *
 * If one address specifies more information than other,
 * e.g. a is INET with a port and b is not, they are not equal.
 *
 * `a` and `b` may be NULL, and NULL == NULL.
 *
 * @param a A pointer to a Address instance
 * @param b A pointer to a Address instance
 * @return true if the two instances are equal
 * @return false if the two instances are not equal
 *
 * Example:
 * @code
 * {
 *     Address *address = addressCreateFromInterface(2);
 *     Address *copy = addressCopy(address);
 *
 *     if (addressEquals(address, copy)) {
 *         // true
 *     }  else {
 *         // false
 *     }
 *
 *     addressDestroy(&address);
 *     addressDestroy(&copy);
 * }
 * @endcode
 */
bool addressEquals(const Address *a, const Address *b);

/**
 * Return the {@link address_type} from a specified Address.
 *
 * @param [in] A pointer to a Address instance
 *
 * @return the {@link address_type} of the specified Address instance
 *
 * Example:
 * @code
 * {
 *     Address *address = addressCreateFromInterface(2);
 *
 *     address_type type = addressGetType(address);
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 *
 * @see address_type
 */
address_type addressGetType(const Address *address);

/**
 * Fills in the output parameter with an INET address.
 *
 * @param addr_in must be non-NULL
 * @return true if INET address and output filled in, false otherwise.
 *
 */
bool addressGetInet(const Address *address, struct sockaddr_in *addr_in);

/**
 * Retrieve the INET6 address associated with a `Address` instance.
 *
 * If the specified Address instance is of type {@link commandAddrType_INET6},
 * then populate the supplied `struct sockaddr_in6` from the Address and return
 * true. If the Address is not of type `commandAddrType_INET6`, this function
 * returns false.
 *
 * @param [in] address A pointer to a `Address` instance of type {@link
 * commandAddrType_INET6}.
 * @param [in] addr_in6 A pointer to a `struct sockaddr_in6`. Must be non-NULL.
 * @return true If the Address instance is of type `commandAddrType_INET6` and
 * `addr_in6` was filled in
 * @return false If the Address instance was not of type `commandAddrType_INET6`
 * or `addr_in6` could not be filled in.
 *
 * @see addressGetType
 */
bool addressGetInet6(const Address *address, struct sockaddr_in6 *addr_in6);

/**
 * Retrieve the interface index associated with a `Address` instance.
 *
 * If the specified `Address` instance is of type {@link commandAddrType_IFACE},
 * then populate the supplied `uint32_t` from the Address and return true. If
 * the `Address` is not of type `commandAddrType_INET6`, this function returns
 * false.
 *
 * @param [in] address A pointer to a `Address` instance of type {@link
 * commandAddrType_IFACE}.
 * @param [in] interfaceIndex A pointer to a `uint32_t` to fill in. Must be
 * non-NULL.
 * @return true If the Address instance is of type `commandAddrType_IFACE` and
 * `interfaceIndex` was filled in.
 * @return false If the Address instance was not of type `commandAddrType_IFACE`
 * or `interfaceIndex` could not be filled in.
 *
 * @see addressGetType
 */
bool addressGetInterfaceIndex(const Address *address, uint32_t *interfaceIndex);

/**
 * Retrieve the link address associated with a `Address` instance.
 *
 * If the specified `Address` instance is of type {@link commandAddrType_LINK},
 * then return a pointer to the {@link PARCBuffer} containing the link address.
 * If the `Address` is not of type {@link commandAddrType_LINK}, then return
 * NULL. The returned PARCBuffer pointer points to memory managed by the Address
 * instance, and does not need to be destroyed or released on its own.
 *
 * @param [in] address A pointer to a `Address` instance of type {@link
 * commandAddrType_LINK}.
 * @return A pointer to the {@link PARCBuffer} containing the link address.
 *
 * Example:
 * @code
 * {
 *     uint8_t mac[] = { 0x14, 0x10, 0x9f, 0xd7, 0x0b, 0x89 };
 *     Address *address = addressCreateFromLink(mac, sizeof(mac));
 *
 *     PARCBuffer *macBuffer = addressGetLinkAddress(address);
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 * @see addressGetType
 */
PARCBuffer *addressGetLinkAddress(const Address *address);

/**
 * Append the string representation of a `Address` to a specified
 * `PARCBufferComposer`.
 *
 * @param [in] address A pointer to a `Address` instance.
 * @param [in] composer A pointer to a `PARCBufferComposer` instance to which to
 * append the string.
 *
 * @return The `PARCBufferComposer` instance that was passed in.
 *
 * Example:
 * @code
 * {
 *     Address *address = addressCreateFromInterface(1);
 *     PARCBufferComposer *composer = addressBuildString(address,
 * parcBufferComposer_Create()); parcBufferComposer_Release(&composer);
 *     addressDestroy(&address);
 * }
 * @endcode
 *
 * @see PARCBufferComposer
 */
PARCBufferComposer *addressBuildString(const Address *address,
                                       PARCBufferComposer *composer);

/**
 * Produce a nil-terminated string representation of the specified instance.
 *
 * The result must be freed by the caller via {@link parcMemory_Deallocate}.
 *
 * @param [in] interest A pointer to the instance.
 *
 * @return NULL Cannot allocate memory.
 * @return non-NULL A pointer to an allocated, nul-terminated C string that must
 * be deallocated via {@link parcMemory_Deallocate}().
 *
 * Example:
 * @code
 * {
 *     Address *address = addressCreateFromInterface(1);
 *
 *     char *string = addressToString(address);
 *
 *     if (string != NULL) {
 *         printf("Address looks like: %s\n", string);
 *         parcMemory_Deallocate(string);
 *     } else {
 *         printf("Cannot allocate memory\n");
 *     }
 *
 *     addressDestroy(&address);
 * }
 * @endcode
 * @see parcMemory_Deallocate
 * @see addressBuildString
 */
char *addressToString(const Address *address);

/**
 * Return a non-cryptographic hash code consistent with Equals
 *
 * If commandAddrA == commandAddrB, then addressHashCode(commandAddrA) ==
 * addressHashCode(commandAddrB)
 *
 * @param [in] address A pointer to a Address instance.
 * @return A 32-bit hashcode for the specified Address instance.
 *
 * Example:
 * @code
 *     Address *address = addressCreateFromInterface(1);
 *
 *     uint32_t hashCode = addressHashCode(address);
 *
 *     addressDestroy(&address);
 * @endcode
 */
PARCHashCode addressHashCode(const Address *address);
#endif  // address_h
