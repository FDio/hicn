/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 * \file ip_address.c
 * \brief Implementation of IP address type
 */

#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>
#include <hicn/util/sstrncpy.h>
#include <hicn/common.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifdef __ANDROID__
#define SWAP(x) bswap_32 (x)
#else
#define SWAP(x) __bswap_constant_32 (x)
#endif
#else
#define SWAP(x) x
#endif

/* No htonl() with const */
const hicn_ip_address_t IPV4_LOOPBACK = {
  .v4.as_inaddr.s_addr = SWAP (INADDR_LOOPBACK),
};

const hicn_ip_address_t IPV6_LOOPBACK = {
  .v6.as_in6addr = IN6ADDR_LOOPBACK_INIT,
};

const hicn_ip_address_t IPV4_ANY = {
  .v4.as_inaddr.s_addr = INADDR_ANY,
};

const hicn_ip_address_t IPV6_ANY = {
  .v6.as_in6addr = IN6ADDR_ANY_INIT,
};

const ipv4_address_t IP4_ADDRESS_EMPTY = {
  .as_u32 = 0,
};

const ipv6_address_t IP6_ADDRESS_EMPTY = {
  .as_u64 = { 0, 0 },
};

const hicn_ip_address_t IP_ADDRESS_EMPTY = {
  .v6.as_u64 = { 0, 0 },
};

/* IP address */

int
hicn_ip_address_get_family (const hicn_ip_address_t *address)
{
  return hicn_ip_address_is_v4 (address) ? AF_INET : AF_INET6;
}

int
hicn_ip_address_str_get_family (const char *ip_address)
{
  struct addrinfo hint, *res = NULL;
  int rc;

  memset (&hint, '\0', sizeof hint);

  hint.ai_family = PF_UNSPEC;
  hint.ai_flags = AI_NUMERICHOST;

  rc = getaddrinfo (ip_address, NULL, &hint, &res);
  if (rc)
    {
      return -1;
    }
  rc = res->ai_family;
  freeaddrinfo (res);
  return rc;
}

int
hicn_ip_address_len (int family)
{
  return (family == AF_INET6) ? IPV6_ADDR_LEN :
	 (family == AF_INET)  ? IPV4_ADDR_LEN :
				      0;
}

int
hicn_ip_address_get_len (const hicn_ip_address_t *ip_address)
{
  return hicn_ip_address_len (hicn_ip_address_get_family (ip_address));
}

int
hicn_ip_address_get_len_bits (const hicn_ip_address_t *ip_address)
{
  return bytes_to_bits (hicn_ip_address_get_len (ip_address));
}

int
hicn_ip_address_ntop (const hicn_ip_address_t *ip_address, char *dst,
		      const size_t len, int family)
{
  const char *s;
  switch (family)
    {
    case AF_INET:
      s = inet_ntop (AF_INET, ip_address->v4.buffer, dst, (socklen_t) len);
      break;
    case AF_INET6:
      s = inet_ntop (AF_INET6, ip_address->v6.buffer, dst, (socklen_t) len);
      break;
    default:
      return -1;
    }
  return (s ? 1 : -1);
}

/*
 * Parse ip addresses in presentation format
 */
int
hicn_ip_address_pton (const char *hicn_ip_address_str,
		      hicn_ip_address_t *ip_address)
{
  int pton_fd;
  int family;

  family = hicn_ip_address_str_get_family (hicn_ip_address_str);

  switch (family)
    {
    case AF_INET:
      ip_address->pad[0] = 0;
      ip_address->pad[1] = 0;
      ip_address->pad[2] = 0;
      pton_fd =
	inet_pton (AF_INET, hicn_ip_address_str, &ip_address->v4.buffer);
      break;
    case AF_INET6:
      pton_fd =
	inet_pton (AF_INET6, hicn_ip_address_str, &ip_address->v6.buffer);
      break;
    default:
      return -1;
    }

  //   0 = not in presentation format
  // < 0 = other error (use perror)
  if (pton_fd <= 0)
    return -1;

  return 1;
}

int
hicn_ip_address_snprintf (char *s, size_t size,
			  const hicn_ip_address_t *ip_address)
{
  const char *rc;
  int family = hicn_ip_address_get_family (ip_address);
  switch (family)
    {
    case AF_INET:
      if (size < INET_ADDRSTRLEN)
	return -1;
      rc = inet_ntop (AF_INET, ip_address->v4.buffer, s, INET_ADDRSTRLEN);
      break;
    case AF_INET6:
      if (size < INET6_ADDRSTRLEN)
	return -1;
      rc = inet_ntop (AF_INET6, ip_address->v6.buffer, s, INET6_ADDRSTRLEN);
      break;
    default:
      return -1;
    }
  if (!rc)
    return -1;
  return (int) strnlen_s (s, MAXSZ_IP_ADDRESS);
}

int
hicn_ip_address_to_sockaddr (const hicn_ip_address_t *ip_address,
			     struct sockaddr *sa, int family)
{
  struct sockaddr_in6 *tmp6 = (struct sockaddr_in6 *) sa;
  struct sockaddr_in *tmp4 = (struct sockaddr_in *) sa;

  switch (family)
    {
    case AF_INET6:
      tmp6->sin6_family = AF_INET6;
      tmp6->sin6_port = DUMMY_PORT;
      tmp6->sin6_scope_id = 0;
      memcpy (&tmp6->sin6_addr, ip_address->v6.buffer, IPV6_ADDR_LEN);
      break;
    case AF_INET:
      tmp4->sin_family = AF_INET;
      tmp4->sin_port = DUMMY_PORT;
      memcpy (&tmp4->sin_addr, ip_address->v4.buffer, IPV4_ADDR_LEN);
      break;
    default:
      return -1;
    }

  return 1;
}

int
hicn_ip_address_cmp (const hicn_ip_address_t *ip1,
		     const hicn_ip_address_t *ip2)
{
  /* This works as soon as all members are initialized */
  return memcmp (ip1, ip2, sizeof (hicn_ip_address_t));
}

bool
hicn_ip_address_equals (const hicn_ip_address_t *ip1,
			const hicn_ip_address_t *ip2)
{
  return hicn_ip_address_cmp (ip1, ip2) == 0;
}

int
hicn_ip_address_empty (const hicn_ip_address_t *ip)
{
  return (memcmp (ip, &IP_ADDRESS_EMPTY, sizeof (hicn_ip_address_t)) == 0);
}

/* Prefix */

/* Parse IP Prefixes in presentation format (in bits, separated by a slash) */
int
hicn_ip_prefix_pton (const char *hicn_ip_address_str,
		     hicn_ip_prefix_t *hicn_ip_prefix)
{
  int pton_fd;
  char *p;
  char *eptr;
  char *addr = strdup (hicn_ip_address_str);

  p = strchr (addr, '/');
  if (!p)
    {
      hicn_ip_prefix->len = ~0; // until we get the ip address family
    }
  else
    {
      hicn_ip_prefix->len = (u8) strtoul (p + 1, &eptr, 10);
      *p = 0;
    }

  hicn_ip_prefix->family = hicn_ip_address_str_get_family (addr);

  switch (hicn_ip_prefix->family)
    {
    case AF_INET6:
      if (hicn_ip_prefix->len == (u8) ~0)
	hicn_ip_prefix->len = IPV6_ADDR_LEN_BITS;
      if (hicn_ip_prefix->len > IPV6_ADDR_LEN_BITS)
	goto ERR;
      pton_fd = inet_pton (AF_INET6, addr, &hicn_ip_prefix->address.v6.buffer);
      break;
    case AF_INET:
      if (hicn_ip_prefix->len == (u8) ~0)
	hicn_ip_prefix->len = IPV4_ADDR_LEN_BITS;
      if (hicn_ip_prefix->len > IPV4_ADDR_LEN_BITS)
	goto ERR;
      pton_fd = inet_pton (AF_INET, addr, &hicn_ip_prefix->address.v4.buffer);
      break;
    default:
      goto ERR;
    }

  //   0 = not in presentation format
  // < 0 = other error (use perror)
  if (pton_fd <= 0)
    goto ERR;

  free (addr);
  return 1;
ERR:
  free (addr);
  return -1;
}

int
hicn_ip_prefix_ntop_short (const hicn_ip_prefix_t *hicn_ip_prefix, char *dst,
			   size_t size)
{
  char ip_s[MAXSZ_IP_ADDRESS];
  const char *s;
  switch (hicn_ip_prefix->family)
    {
    case AF_INET:
      s = inet_ntop (AF_INET, hicn_ip_prefix->address.v4.buffer, ip_s,
		     MAXSZ_IP_ADDRESS);
      break;
    case AF_INET6:
      s = inet_ntop (AF_INET6, hicn_ip_prefix->address.v6.buffer, ip_s,
		     MAXSZ_IP_ADDRESS);
      break;
    default:
      return -1;
    }
  if (!s)
    return -1;
  int rc = snprintf (dst, size, "%s", ip_s);
  if (rc >= size)
    return (int) size;
  return rc;
}

int
hicn_ip_prefix_ntop (const hicn_ip_prefix_t *hicn_ip_prefix, char *dst,
		     size_t size)
{
  char ip_s[MAXSZ_IP_ADDRESS];
  const char *s;
  switch (hicn_ip_prefix->family)
    {
    case AF_INET:
      s = inet_ntop (AF_INET, hicn_ip_prefix->address.v4.buffer, ip_s,
		     MAXSZ_IP_ADDRESS);
      break;
    case AF_INET6:
      s = inet_ntop (AF_INET6, hicn_ip_prefix->address.v6.buffer, ip_s,
		     MAXSZ_IP_ADDRESS);
      break;
    default:
      return -1;
    }
  if (!s)
    return -1;
  int rc = snprintf (dst, size, "%s/%d", ip_s, hicn_ip_prefix->len);
  if (rc >= size)
    return (int) size;
  return rc;
}

int
hicn_ip_prefix_snprintf (char *s, size_t size, const hicn_ip_prefix_t *prefix)
{
  return hicn_ip_prefix_ntop (prefix, s, size);
}

int
hicn_ip_prefix_len (const hicn_ip_prefix_t *prefix)
{
  return prefix->len; // hicn_ip_address_len(&prefix->address, prefix->family);
}

const u8 *
hicn_ip_address_get_buffer (const hicn_ip_address_t *ip_address, int family)
{
  switch (family)
    {
    case AF_INET:
      return ip_address->v4.buffer;
    case AF_INET6:
      return ip_address->v6.buffer;
    default:
      return NULL;
    }
}

bool
hicn_ip_prefix_empty (const hicn_ip_prefix_t *prefix)
{
  return prefix->len == 0;
}

int
hicn_ip_prefix_to_sockaddr (const hicn_ip_prefix_t *prefix,
			    struct sockaddr *sa)
{
  // XXX assert len == hicn_ip_address_len
  return hicn_ip_address_to_sockaddr (&prefix->address, sa, prefix->family);
}

int
hicn_ip_prefix_cmp (const hicn_ip_prefix_t *prefix1,
		    const hicn_ip_prefix_t *prefix2)
{
  if (prefix1->family < prefix2->family)
    return -1;
  else if (prefix1->family > prefix2->family)
    return 1;

  if (prefix1->len < prefix2->len)
    return -1;
  else if (prefix1->len > prefix2->len)
    return 1;

  return hicn_ip_address_cmp (&prefix1->address, &prefix2->address);
}

uint8_t
hicn_ip_address_get_bit (const hicn_ip_address_t *address, uint8_t pos)
{
  u64 quad = address->v6.as_u64[pos / 64];
  return quad & (0x1 << pos % 64);
}

bool
hicn_ip_address_match_family (const hicn_ip_address_t *address, int family)
{
  return hicn_ip_address_get_family (address) == family;
}

uint32_t
hicn_ip_address_get_hash (const hicn_ip_address_t *address)
{
  return hash32 (address, sizeof (address));
}

/* URL */

#define MAXSZ_PROTO_ 8 /* inetX:// */
#define MAXSZ_PROTO  MAXSZ_PROTO_ + NULLTERM

#define MAXSZ_URL4_ MAXSZ_PROTO_ + MAXSZ_IP4_ADDRESS_ + MAXSZ_PORT_
#define MAXSZ_URL6_ MAXSZ_PROTO_ + MAXSZ_IP6_ADDRESS_ + MAXSZ_PORT_
#define MAXSZ_URL_  MAXSZ_URL6_
#define MAXSZ_URL4  MAXSZ_URL4_ + NULLTERM
#define MAXSZ_URL6  MAXSZ_URL6_ + NULLTERM
#define MAXSZ_URL   MAXSZ_URL_ + NULLTERM

int
url_snprintf (char *s, size_t size, const hicn_ip_address_t *ip_address,
	      u16 port)
{
  char hicn_ip_address_s[MAXSZ_IP_ADDRESS];
  int rc;

  int family = hicn_ip_address_get_family (ip_address);

  /* Other address are currently not supported */
  if (!IS_VALID_FAMILY (family))
    return -1;

  if (!hicn_ip_address_match_family (ip_address, family))
    return -1;
  rc =
    hicn_ip_address_snprintf (hicn_ip_address_s, MAXSZ_IP_ADDRESS, ip_address);
  if (rc >= MAXSZ_IP_ADDRESS)
    WARN ("[url_snprintf] Unexpected ip_address truncation");
  if (rc < 0)
    return rc;

  return snprintf (s, size, "inet%c://%s:%d", (family == AF_INET) ? '4' : '6',
		   hicn_ip_address_s, port);
}
