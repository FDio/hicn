#pragma once
#define WIN32_LEAN_AND_MEAN
#include <afunix.h>
#include <assert.h>
#include <errno.h>
#include <in6addr.h>
#include <io.h>
#include <iphlpapi.h>
#include <process.h>
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <winsock2.h>
#include <winternl.h>
#include <ws2tcpip.h>
#pragma comment(lib, "IPHLPAPI.lib")
#include <parc/windows/parc_Utils.h>

#ifndef in_port_t
#define in_port_t uint16_t
#endif

#ifndef in_addr_t
#define in_addr_t uint32_t
#endif

#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

#define HAVE_STRUCT_TIMESPEC

#ifndef getline
int getline(char **lineptr, size_t *n, FILE *stream);
#endif