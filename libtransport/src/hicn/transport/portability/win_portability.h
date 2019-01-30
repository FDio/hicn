#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <parc/windows/parc_Utils.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <algorithm>

#define __ORDER_LITTLE_ENDIAN__ 0x41424344UL
#define __ORDER_BIG_ENDIAN__ 0x44434241UL
#define __BYTE_ORDER__ ('ABCD')
#undef DELETE

#define HAVE_STRUCT_TIMESPEC
#include <pthread.h>

#ifndef GETTIMEOFDAY
#define GETTIMEOFDAY
int gettimeofday(struct timeval* tp, struct timezone* tzp);
#endif

#ifndef USLEEP
#define USLEEP
void usleep(__int64 usec);
#endif