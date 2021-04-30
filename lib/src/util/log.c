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

#include <hicn/util/log.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

log_conf_t log_conf = DEFAULT_LOG_CONF;

#define FMT_DATETIME "%02d-%02d-%04d %02d:%02d:%02d"
#define FMT_DATETIME_LEN 20
#define snprintf_nowarn(...) (snprintf(__VA_ARGS__) < 0 ? abort() : (void)0)


static char ts[FMT_DATETIME_LEN];

static char *timestamp(void)
{
	time_t tv;
	struct tm *tm;

	time(&tv);
	tm = localtime(&tv);

        snprintf_nowarn(ts, FMT_DATETIME_LEN, FMT_DATETIME, tm->tm_mday,
                tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min,
                tm->tm_sec);
	return ts;
}

void _log_va(int level, const char *fmt, va_list ap)
{  

#if 0
	if (!conf.log_system)
		return;
#endif

	char *prefix;

#ifdef __ANDROID__
	int prio = -1;
	if (level > log_conf.log_level)
		return;

	switch (level) {
		case LOG_FATAL:
			prio = ANDROID_LOG_FATAL;
			prefix = "FATAL: ";
			break;
		case LOG_ERROR:
			prio = ANDROID_LOG_ERROR;
			prefix = "ERROR: ";
			break;
		case LOG_WARN:
			prio = ANDROID_LOG_WARN;
			prefix = "WARNING: ";
			break;
		case LOG_INFO:
			prio = ANDROID_LOG_INFO;
			prefix = "";
			break;
		case LOG_DEBUG:
			prio  = ANDROID_LOG_DEBUG;
			prefix = "DEBUG: ";
			break;
		case LOG_TRACE:
			prio = ANDROID_LOG_DEBUG;
			prefix = "TRACE: ";
			break;
		default:
			prio = ANDROID_LOG_INFO;
			prefix = "";
			break;
	}

	if (log_conf.log_file) {
		FILE *f = log_conf.log_file;
		fprintf(f, "%s %s", timestamp(), prefix);
		vfprintf(f, fmt, ap);
		fprintf(f, "\n");
	} else {
		__android_log_vprint(ANDROID_LOG_INFO, "HICN FACEMGR", fmt, ap);
	}

#else

	if (level > log_conf.log_level)
		return;

	switch (level) {
		case LOG_FATAL:
			prefix = "FATAL: ";
			break;
		case LOG_ERROR:
			prefix = "ERROR: ";
			break;
		case LOG_WARN:
			prefix = "WARNING: ";
			break;
		case LOG_INFO:
			prefix = "";
			break;
		case LOG_DEBUG:
			prefix = "DEBUG: ";
			break;
		case LOG_TRACE:
			prefix = "TRACE: ";
			break;
		default:
			prefix = "";
			break;
	}
	FILE *f = log_conf.log_file ? log_conf.log_file : stdout;
	fprintf(f, "%s %s", timestamp(), prefix);
	vfprintf(f, fmt, ap);
	fprintf(f, "\n");
#ifdef DEBUG
	fflush(f);
#endif
#endif
}

void _log(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_log_va(level, fmt, ap);
	va_end(ap);
}

#ifdef HAVE_BACKTRACE
#include <execinfo.h>

void print_trace(void)
{
	void *array[32];
	size_t size;

	size = backtrace(array, 32);
	fflush(conf.log_file);
	backtrace_symbols_fd(array, size, fileno(conf.log_file));
}
#endif

void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_log_va(LOG_FATAL, fmt, ap);
	va_end(ap);

#ifdef HAVE_BACKTRACE
	print_trace();
#endif

	exit(200);
}
