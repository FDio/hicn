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

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 wonder-mice
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* When defined, Android log (android/log.h) will be used by default instead of
 * stderr (ignored on non-Android platforms). Date, time, pid and tid (context)
 * will be provided by Android log. Android log features will be used to output
 * log level and tag.
 */

#if defined(__ANDROID__)
#define TRANSPORT_LOG_USE_ANDROID_LOG 1
#define ANDROID_TAG "HicnTransport"
#else
#define TRANSPORT_LOG_USE_ANDROID_LOG 0
#endif

/* When defined, NSLog (uses Apple System Log) will be used instead of stderr
 * (ignored on non-Apple platforms). Date, time, pid and tid (context) will be
 * provided by NSLog. Curiously, doesn't use NSLog() directly, but piggybacks on
 * non-public CFLog() function. Both use Apple System Log internally, but it's
 * easier to call CFLog() from C than NSLog(). Current implementation doesn't
 * support "%@" format specifier.
 */
#ifdef TRANSPORT_LOG_USE_NSLOG
#undef TRANSPORT_LOG_USE_NSLOG
#if defined(__APPLE__) && defined(__MACH__)
#define TRANSPORT_LOG_USE_NSLOG 1
#else
#define TRANSPORT_LOG_USE_NSLOG 0
#endif
#else
#define TRANSPORT_LOG_USE_NSLOG 0
#endif
/* When defined, OutputDebugString() will be used instead of stderr (ignored on
 * non-Windows platforms). Uses OutputDebugStringA() variant and feeds it with
 * UTF-8 data.
 */
#ifdef TRANSPORT_LOG_USE_DEBUGSTRING
#undef TRANSPORT_LOG_USE_DEBUGSTRING
#if defined(_WIN32) || defined(_WIN64)
#define TRANSPORT_LOG_USE_DEBUGSTRING 1
#else
#define TRANSPORT_LOG_USE_DEBUGSTRING 0
#endif
#else
#define TRANSPORT_LOG_USE_DEBUGSTRING 0
#endif
/* When defined, TRANSPORT_LOG library will not contain definition of tag prefix
 * variable. In that case it must be defined elsewhere using
 * TRANSPORT_LOG_DEFINE_TAG_PREFIX macro, for example:
 *
 *   TRANSPORT_LOG_DEFINE_TAG_PREFIX = "ProcessName";
 *
 * This allows to specify custom value for static initialization and avoid
 * overhead of setting this value in runtime.
 */
#ifdef TRANSPORT_LOG_EXTERN_TAG_PREFIX
#undef TRANSPORT_LOG_EXTERN_TAG_PREFIX
#define TRANSPORT_LOG_EXTERN_TAG_PREFIX 1
#else
#define TRANSPORT_LOG_EXTERN_TAG_PREFIX 0
#endif
/* When defined, TRANSPORT_LOG library will not contain definition of global
 * format variable. In that case it must be defined elsewhere using
 * TRANSPORT_LOG_DEFINE_GLOBAL_FORMAT macro, for example:
 *
 *   TRANSPORT_LOG_DEFINE_GLOBAL_FORMAT = {MEM_WIDTH};
 *
 * This allows to specify custom value for static initialization and avoid
 * overhead of setting this value in runtime.
 */
#ifdef TRANSPORT_LOG_EXTERN_GLOBAL_FORMAT
#undef TRANSPORT_LOG_EXTERN_GLOBAL_FORMAT
#define TRANSPORT_LOG_EXTERN_GLOBAL_FORMAT 1
#else
#define TRANSPORT_LOG_EXTERN_GLOBAL_FORMAT 0
#endif
/* When defined, transport_log library will not contain definition of global
 * output variable. In that case it must be defined elsewhere using
 * TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT macro, for example:
 *
 *   TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT = {TRANSPORT_LOG_PUT_STD,
 * custom_output_callback};
 *
 * This allows to specify custom value for static initialization and avoid
 * overhead of setting this value in runtime.
 */
#ifdef TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT
#undef TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT
#define TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT 1
#else
#define TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT 0
#endif
/* When defined, transport_log library will not contain definition of global
 * output level variable. In that case it must be defined elsewhere using
 * TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT_LEVEL macro, for example:
 *
 *   TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT_LEVEL = TRANSPORT_LOG_WARN;
 *
 * This allows to specify custom value for static initialization and avoid
 * overhead of setting this value in runtime.
 */
#ifdef TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL
#undef TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL
#define TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL 1
#else
#define TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL 0
#endif
/* When defined, implementation will prefer smaller code size over speed.
 * Very rough estimate is that code will be up to 2x smaller and up to 2x
 * slower. Disabled by default.
 */
#ifdef TRANSPORT_LOG_OPTIMIZE_SIZE
#undef TRANSPORT_LOG_OPTIMIZE_SIZE
#define TRANSPORT_LOG_OPTIMIZE_SIZE 1
#else
#define TRANSPORT_LOG_OPTIMIZE_SIZE 0
#endif
/* Size of the log line buffer. The buffer is allocated on stack. It limits
 * maximum length of a log line.
 */
#ifndef TRANSPORT_LOG_BUF_SZ
#define TRANSPORT_LOG_BUF_SZ 512
#endif
/* Default number of bytes in one line of memory output. For large values
 * TRANSPORT_LOG_BUF_SZ also must be increased.
 */
#ifndef TRANSPORT_LOG_MEM_WIDTH
#define TRANSPORT_LOG_MEM_WIDTH 32
#endif
/* String to put in the end of each log line (can be empty). Its value used by
 * stderr output callback. Its size used as a default value for
 * TRANSPORT_LOG_EOL_SZ.
 */
#ifndef TRANSPORT_LOG_EOL
#define TRANSPORT_LOG_EOL "\n"
#endif
/* Default delimiter that separates parts of log message. Can NOT contain '%'
 * or '\0'.
 *
 * Log message format specifications can override (or ignore) this value. For
 * more details see TRANSPORT_LOG_MESSAGE_CTX_FORMAT,
 * TRANSPORT_LOG_MESSAGE_SRC_FORMAT and TRANSPORT_LOG_MESSAGE_TAG_FORMAT.
 */
#ifndef TRANSPORT_LOG_DEF_DELIMITER
#define TRANSPORT_LOG_DEF_DELIMITER " "
#endif
/* Specifies log message context format. Log message context includes date,
 * time, process id, thread id and message's log level. Custom information can
 * be added as well. Supported fields: YEAR, MONTH, DAY, HOUR, MINUTE, SECOND,
 * MILLISECOND, PID, TID, LEVEL, S(str), F_INIT(statements),
 * F_UINT(width, value).
 *
 * Must be defined as a tuple, for example:
 *
 *   #define TRANSPORT_LOG_MESSAGE_CTX_FORMAT (YEAR, S("."), MONTH, S("."), DAY,
 * S(" > "))
 *
 * In that case, resulting log message will be:
 *
 *   2016.12.22 > TAG function@filename.c:line Message text
 *
 * Note, that tag, source location and message text are not impacted by
 * this setting. See TRANSPORT_LOG_MESSAGE_TAG_FORMAT and
 * TRANSPORT_LOG_MESSAGE_SRC_FORMAT.
 *
 * If message context must be visually separated from the rest of the message,
 * it must be reflected in context format (notice trailing S(" > ") in the
 * example above).
 *
 * S(str) adds constant string str. String can NOT contain '%' or '\0'.
 *
 * F_INIT(statements) adds initialization statement(s) that will be evaluated
 * once for each log message. All statements are evaluated in specified order.
 * Several F_INIT() fields can be used in every log message format
 * specification. Fields, like F_UINT(width, value), are allowed to use results
 * of initialization statements. If statement introduces variables (or other
 * names, like structures) they must be prefixed with "f_". Statements  must be
 * enclosed into additional "()". Example:
 *
 *   #define TRANSPORT_LOG_MESSAGE_CTX_FORMAT \
 *       (F_INIT(( struct rusage f_ru; getrusage(RUSAGE_SELF, &f_ru); )), \
 *        YEAR, S("."), MONTH, S("."), DAY, S(" "), \
 *        F_UINT(5, f_ru.ru_nsignals), \
 *        S(" "))
 *
 * F_UINT(width, value) adds unsigned integer value extended with up to width
 * spaces (for alignment purposes). Value can be any expression that evaluates
 * to unsigned integer. If expression contains non-standard functions, they
 * must be declared with F_INIT(). Example:
 *
 *   #define TRANSPORT_LOG_MESSAGE_CTX_FORMAT \
 *        (YEAR, S("."), MONTH, S("."), DAY, S(" "), \
 *        F_INIT(( unsigned tickcount(); )), \
 *        F_UINT(5, tickcount()), \
 *        S(" "))
 *
 * Other log message format specifications follow same rules, but have a
 * different set of supported fields.
 */
#ifndef TRANSPORT_LOG_MESSAGE_CTX_FORMAT
#define TRANSPORT_LOG_MESSAGE_CTX_FORMAT                                       \
  (MONTH, S("-"), DAY, S(TRANSPORT_LOG_DEF_DELIMITER), HOUR, S(":"), MINUTE,   \
   S(":"), SECOND, S("."), MILLISECOND, S(TRANSPORT_LOG_DEF_DELIMITER), PID,   \
   S(TRANSPORT_LOG_DEF_DELIMITER), TID, S(TRANSPORT_LOG_DEF_DELIMITER), LEVEL, \
   S(TRANSPORT_LOG_DEF_DELIMITER))
#endif
/* Example:
 */
/* Specifies log message tag format. It includes tag prefix and tag. Custom
 * information can be added as well. Supported fields:
 * TAG(prefix_delimiter, tag_delimiter), S(str), F_INIT(statements),
 * F_UINT(width, value).
 *
 * TAG(prefix_delimiter, tag_delimiter) adds following string to log message:
 *
 *   PREFIX<prefix_delimiter>TAG<tag_delimiter>
 *
 * Prefix delimiter will be used only when prefix is not empty. Tag delimiter
 * will be used only when prefixed tag is not empty. Example:
 *
 *   #define TRANSPORT_LOG_TAG_FORMAT (S("["), TAG(".", ""), S("] "))
 *
 * See TRANSPORT_LOG_MESSAGE_CTX_FORMAT for details.
 */
#ifndef TRANSPORT_LOG_MESSAGE_TAG_FORMAT
#define TRANSPORT_LOG_MESSAGE_TAG_FORMAT (TAG(".", TRANSPORT_LOG_DEF_DELIMITER))
#endif
/* Specifies log message source location format. It includes function name,
 * file name and file line. Custom information can be added as well. Supported
 * fields: FUNCTION, FILENAME, FILELINE, S(str), F_INIT(statements),
 * F_UINT(width, value).
 *
 * See TRANSPORT_LOG_MESSAGE_CTX_FORMAT for details.
 */
#ifndef TRANSPORT_LOG_MESSAGE_SRC_FORMAT
#define TRANSPORT_LOG_MESSAGE_SRC_FORMAT \
  (FUNCTION, S("@"), FILENAME, S(":"), FILELINE, S(TRANSPORT_LOG_DEF_DELIMITER))
#endif
/* Fields that can be used in log message format specifications (see above).
 * Mentioning them here explicitly, so we know that nobody else defined them
 * before us. See TRANSPORT_LOG_MESSAGE_CTX_FORMAT for details.
 */
#define YEAR YEAR
#define MONTH MONTH
#define DAY DAY
#define MINUTE MINUTE
#define SECOND SECOND
#define MILLISECOND MILLISECOND
#define PID PID
#define TID TID
#define LEVEL LEVEL
#define TAG(prefix_delim, tag_delim) TAG(prefix_delim, tag_delim)
#define FUNCTION FUNCTION
#define FILENAME FILENAME
#define FILELINE FILELINE
#define S(str) S(str)
#define F_INIT(statements) F_INIT(statements)
#define F_UINT(width, value) F_UINT(width, value)
/* Number of bytes to reserve for EOL in the log line buffer (must be >0).
 * Must be larger than or equal to length of TRANSPORT_LOG_EOL with terminating
 * null.
 */
#ifndef TRANSPORT_LOG_EOL_SZ
#define TRANSPORT_LOG_EOL_SZ sizeof(TRANSPORT_LOG_EOL)
#endif
/* Compile instrumented version of the library to facilitate unit testing.
 */
#ifndef TRANSPORT_LOG_INSTRUMENTED
#define TRANSPORT_LOG_INSTRUMENTED 0
#endif

#if defined(__linux__)
#if !defined(__ANDROID__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#endif
#if defined(__MINGW32__)
#ifdef __STRICT_ANSI__
#undef __STRICT_ANSI__
#endif
#endif

#include <assert.h>
#include <ctype.h>
#include <hicn/transport/utils/log.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif
#endif

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/types.h>
#if !defined(__ANDROID__)
#include <sys/syscall.h>
#endif
#endif
#if defined(__MACH__)
#include <pthread.h>
#endif

#define INLINE _TRANSPORT_LOG_INLINE
#define VAR_UNUSED(var) (void)var
#define RETVAL_UNUSED(expr) \
  do {                      \
    while (expr) break;     \
  } while (0)
#define STATIC_ASSERT(name, cond) typedef char assert_##name[(cond) ? 1 : -1]
#define ASSERT_UNREACHABLE(why) assert(!sizeof(why))
#ifndef _countof
#define _countof(xs) (sizeof(xs) / sizeof((xs)[0]))
#endif

#if TRANSPORT_LOG_INSTRUMENTED
#define INSTRUMENTED_CONST
#else
#define INSTRUMENTED_CONST const
#endif

#define _PP_PASTE_2(a, b) a##b
#define _PP_CONCAT_2(a, b) _PP_PASTE_2(a, b)

#define _PP_PASTE_3(a, b, c) a##b##c
#define _PP_CONCAT_3(a, b, c) _PP_PASTE_3(a, b, c)

/* Microsoft C preprocessor is a piece of shit. This moron treats __VA_ARGS__
 * as a single token and requires additional expansion to realize that it's
 * actually a list. If not for it, there would be no need in this extra
 * expansion.
 */
#define _PP_ID(x) x
#define _PP_NARGS_N(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, \
                    _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, \
                    _24, ...)                                              \
  _24
#define _PP_NARGS(...)                                                        \
  _PP_ID(_PP_NARGS_N(__VA_ARGS__, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, \
                     13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0))

/* There is a more efficient way to implement this, but it requires
 * working C preprocessor. Unfortunately, Microsoft Visual Studio doesn't
 * have one.
 */
#define _PP_HEAD__(x, ...) x
#define _PP_HEAD_(...) _PP_ID(_PP_HEAD__(__VA_ARGS__, ~))
#define _PP_HEAD(xs) _PP_HEAD_ xs
#define _PP_TAIL_(x, ...) (__VA_ARGS__)
#define _PP_TAIL(xs) _PP_TAIL_ xs
#define _PP_UNTUPLE_(...) __VA_ARGS__
#define _PP_UNTUPLE(xs) _PP_UNTUPLE_ xs

/* Apply function macro to each element in tuple. Output is not
 * enforced to be a tuple.
 */
#define _PP_MAP_1(f, xs) f(_PP_HEAD(xs))
#define _PP_MAP_2(f, xs) f(_PP_HEAD(xs)) _PP_MAP_1(f, _PP_TAIL(xs))
#define _PP_MAP_3(f, xs) f(_PP_HEAD(xs)) _PP_MAP_2(f, _PP_TAIL(xs))
#define _PP_MAP_4(f, xs) f(_PP_HEAD(xs)) _PP_MAP_3(f, _PP_TAIL(xs))
#define _PP_MAP_5(f, xs) f(_PP_HEAD(xs)) _PP_MAP_4(f, _PP_TAIL(xs))
#define _PP_MAP_6(f, xs) f(_PP_HEAD(xs)) _PP_MAP_5(f, _PP_TAIL(xs))
#define _PP_MAP_7(f, xs) f(_PP_HEAD(xs)) _PP_MAP_6(f, _PP_TAIL(xs))
#define _PP_MAP_8(f, xs) f(_PP_HEAD(xs)) _PP_MAP_7(f, _PP_TAIL(xs))
#define _PP_MAP_9(f, xs) f(_PP_HEAD(xs)) _PP_MAP_8(f, _PP_TAIL(xs))
#define _PP_MAP_10(f, xs) f(_PP_HEAD(xs)) _PP_MAP_9(f, _PP_TAIL(xs))
#define _PP_MAP_11(f, xs) f(_PP_HEAD(xs)) _PP_MAP_10(f, _PP_TAIL(xs))
#define _PP_MAP_12(f, xs) f(_PP_HEAD(xs)) _PP_MAP_11(f, _PP_TAIL(xs))
#define _PP_MAP_13(f, xs) f(_PP_HEAD(xs)) _PP_MAP_12(f, _PP_TAIL(xs))
#define _PP_MAP_14(f, xs) f(_PP_HEAD(xs)) _PP_MAP_13(f, _PP_TAIL(xs))
#define _PP_MAP_15(f, xs) f(_PP_HEAD(xs)) _PP_MAP_14(f, _PP_TAIL(xs))
#define _PP_MAP_16(f, xs) f(_PP_HEAD(xs)) _PP_MAP_15(f, _PP_TAIL(xs))
#define _PP_MAP_17(f, xs) f(_PP_HEAD(xs)) _PP_MAP_16(f, _PP_TAIL(xs))
#define _PP_MAP_18(f, xs) f(_PP_HEAD(xs)) _PP_MAP_17(f, _PP_TAIL(xs))
#define _PP_MAP_19(f, xs) f(_PP_HEAD(xs)) _PP_MAP_18(f, _PP_TAIL(xs))
#define _PP_MAP_20(f, xs) f(_PP_HEAD(xs)) _PP_MAP_19(f, _PP_TAIL(xs))
#define _PP_MAP_21(f, xs) f(_PP_HEAD(xs)) _PP_MAP_20(f, _PP_TAIL(xs))
#define _PP_MAP_22(f, xs) f(_PP_HEAD(xs)) _PP_MAP_21(f, _PP_TAIL(xs))
#define _PP_MAP_23(f, xs) f(_PP_HEAD(xs)) _PP_MAP_22(f, _PP_TAIL(xs))
#define _PP_MAP_24(f, xs) f(_PP_HEAD(xs)) _PP_MAP_23(f, _PP_TAIL(xs))
#define _PP_MAP(f, xs) _PP_CONCAT_2(_PP_MAP_, _PP_NARGS xs)(f, xs)

/* Apply function macro to each element in tuple in reverse order.
 * Output is not enforced to be a tuple.
 */
#define _PP_RMAP_1(f, xs) f(_PP_HEAD(xs))
#define _PP_RMAP_2(f, xs) _PP_RMAP_1(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_3(f, xs) _PP_RMAP_2(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_4(f, xs) _PP_RMAP_3(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_5(f, xs) _PP_RMAP_4(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_6(f, xs) _PP_RMAP_5(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_7(f, xs) _PP_RMAP_6(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_8(f, xs) _PP_RMAP_7(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_9(f, xs) _PP_RMAP_8(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_10(f, xs) _PP_RMAP_9(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_11(f, xs) _PP_RMAP_10(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_12(f, xs) _PP_RMAP_11(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_13(f, xs) _PP_RMAP_12(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_14(f, xs) _PP_RMAP_13(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_15(f, xs) _PP_RMAP_14(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_16(f, xs) _PP_RMAP_15(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_17(f, xs) _PP_RMAP_16(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_18(f, xs) _PP_RMAP_17(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_19(f, xs) _PP_RMAP_18(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_20(f, xs) _PP_RMAP_19(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_21(f, xs) _PP_RMAP_20(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_22(f, xs) _PP_RMAP_21(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_23(f, xs) _PP_RMAP_22(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP_24(f, xs) _PP_RMAP_23(f, _PP_TAIL(xs)) f(_PP_HEAD(xs))
#define _PP_RMAP(f, xs) _PP_CONCAT_2(_PP_RMAP_, _PP_NARGS xs)(f, xs)

/* Used to implement _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS() macro. All
 * possible fields must be mentioned here. Not counting F_INIT() here because
 * it's somewhat special and is handled spearatly (at least for now).
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__ (0 << 0)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__YEAR (1 << 1)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__MONTH (1 << 2)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__DAY (1 << 3)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__HOUR (1 << 4)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__MINUTE (1 << 5)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__SECOND (1 << 6)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__MILLISECOND (1 << 7)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__PID (1 << 8)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__TID (1 << 9)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__LEVEL (1 << 10)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__TAG(ps, ts) (1 << 11)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__FUNCTION (1 << 12)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__FILENAME (1 << 13)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__FILELINE (1 << 14)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__S(s) (1 << 15)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__F_INIT(expr) (0 << 16)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK__F_UINT(w, v) (1 << 17)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_MASK(field) \
  _PP_CONCAT_3(_TRANSPORT_LOG_MESSAGE_FORMAT_MASK_, _, field)

/* Logical "or" of masks of fields used in specified format specification.
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_FIELDS(format) \
  (0 _PP_MAP(| _TRANSPORT_LOG_MESSAGE_FORMAT_MASK, format))

/* Expands to expressions that evaluates to true if field is used in
 * specified format specification. Example:
 *
 *   #if _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(F_UINT,
 * TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
 *       ...
 *   #endif
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(field, format) \
  (_TRANSPORT_LOG_MESSAGE_FORMAT_MASK(field) &                \
   _TRANSPORT_LOG_MESSAGE_FORMAT_FIELDS(format))

/* Same, but checks all supported format specifications.
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_FIELD_USED(field)                        \
  (_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(field,                               \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(field,                               \
                                          TRANSPORT_LOG_MESSAGE_TAG_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(field,                               \
                                          TRANSPORT_LOG_MESSAGE_SRC_FORMAT))

#define _TRANSPORT_LOG_MESSAGE_FORMAT_DATETIME_USED                            \
  (_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(YEAR,                                \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(MONTH,                               \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(DAY,                                 \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(HOUR,                                \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(MINUTE,                              \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(SECOND,                              \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT) || \
   _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(MILLISECOND,                         \
                                          TRANSPORT_LOG_MESSAGE_CTX_FORMAT))

#if defined(_MSC_VER) && !defined(__INTEL_COMPILER)
#pragma warning(disable : 4204) /* nonstandard extension used: non-constant \
                                   aggregate initializer */
#define memccpy _memccpy
#endif

#if (defined(_MSC_VER) && !defined(__INTEL_COMPILER)) || defined(__MINGW64__)
#define vsnprintf(s, sz, fmt, va) fake_vsnprintf(s, sz, fmt, va)
static int fake_vsnprintf(char *s, size_t sz, const char *fmt, va_list ap) {
  const int n = vsnprintf_s(s, sz, _TRUNCATE, fmt, ap);
  return 0 < n ? n : (int)sz + 1; /* no need in _vscprintf() for now */
}
#if TRANSPORT_LOG_OPTIMIZE_SIZE
#define snprintf(s, sz, ...) fake_snprintf(s, sz, __VA_ARGS__)
static int fake_snprintf(char *s, size_t sz, const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  const int n = fake_vsnprintf(s, sz, fmt, va);
  va_end(va);
  return n;
}
#endif
#endif

typedef void (*time_cb)(struct tm *const tm, unsigned *const usec);
typedef void (*pid_cb)(int *const pid, int *const tid);
typedef void (*buffer_cb)(transport_log_message *msg, char *buf);

typedef struct src_location {
  const char *const func;
  const char *const file;
  const unsigned line;
} src_location;

typedef struct mem_block {
  const void *const d;
  const unsigned d_sz;
} mem_block;

static void time_callback(struct tm *const tm, unsigned *const usec);
static void pid_callback(int *const pid, int *const tid);
static void buffer_callback(transport_log_message *msg, char *buf);

STATIC_ASSERT(eol_fits_eol_sz,
              sizeof(TRANSPORT_LOG_EOL) <= TRANSPORT_LOG_EOL_SZ);
STATIC_ASSERT(eol_sz_greater_than_zero, 0 < TRANSPORT_LOG_EOL_SZ);
STATIC_ASSERT(eol_sz_less_than_buf_sz,
              TRANSPORT_LOG_EOL_SZ < TRANSPORT_LOG_BUF_SZ);
#if !defined(_WIN32) && !defined(_WIN64)
STATIC_ASSERT(buf_sz_less_than_pipe_buf, TRANSPORT_LOG_BUF_SZ <= PIPE_BUF);
#endif
static const char c_hex[] = "0123456789abcdef";

static INSTRUMENTED_CONST unsigned g_buf_sz =
    TRANSPORT_LOG_BUF_SZ - TRANSPORT_LOG_EOL_SZ;
static INSTRUMENTED_CONST time_cb g_time_cb = time_callback;
static INSTRUMENTED_CONST pid_cb g_pid_cb = pid_callback;
static INSTRUMENTED_CONST buffer_cb g_buffer_cb = buffer_callback;

#if TRANSPORT_LOG_USE_ANDROID_LOG
#include <android/log.h>

static INLINE int android_lvl(const int lvl) {
  switch (lvl) {
    case TRANSPORT_LOG_VERBOSE:
      return ANDROID_LOG_VERBOSE;
    case TRANSPORT_LOG_DEBUG:
      return ANDROID_LOG_DEBUG;
    case TRANSPORT_LOG_INFO:
      return ANDROID_LOG_INFO;
    case TRANSPORT_LOG_WARN:
      return ANDROID_LOG_WARN;
    case TRANSPORT_LOG_ERROR:
      return ANDROID_LOG_ERROR;
    case TRANSPORT_LOG_FATAL:
      return ANDROID_LOG_FATAL;
    default:
      ASSERT_UNREACHABLE("Bad log level");
      return ANDROID_LOG_UNKNOWN;
  }
}

static void out_android_callback(const transport_log_message *const msg,
                                 void *arg) {
  VAR_UNUSED(arg);
  *msg->p = 0;
  const char *tag = msg->p;
  if (msg->tag_e != msg->tag_b) {
    tag = msg->tag_b;
    *msg->tag_e = 0;
  }
  __android_log_print(android_lvl(msg->lvl), ANDROID_TAG, "%s", msg->msg_b);
}

enum { OUT_ANDROID_MASK = TRANSPORT_LOG_PUT_STD & ~TRANSPORT_LOG_PUT_CTX };
#define OUT_ANDROID OUT_ANDROID_MASK, 0, out_android_callback
#endif

#if TRANSPORT_LOG_USE_NSLOG
#include <CoreFoundation/CoreFoundation.h>
CF_EXPORT void CFLog(int32_t level, CFStringRef format, ...);

static INLINE int apple_lvl(const int lvl) {
  switch (lvl) {
    case TRANSPORT_LOG_VERBOSE:
      return 7; /* ASL_LEVEL_DEBUG / kCFLogLevelDebug */
      ;
    case TRANSPORT_LOG_DEBUG:
      return 7; /* ASL_LEVEL_DEBUG / kCFLogLevelDebug */
      ;
    case TRANSPORT_LOG_INFO:
      return 6; /* ASL_LEVEL_INFO / kCFLogLevelInfo */
      ;
    case TRANSPORT_LOG_WARN:
      return 4; /* ASL_LEVEL_WARNING / kCFLogLevelWarning */
      ;
    case TRANSPORT_LOG_ERROR:
      return 3; /* ASL_LEVEL_ERR / kCFLogLevelError */
      ;
    case TRANSPORT_LOG_FATAL:
      return 0; /* ASL_LEVEL_EMERG / kCFLogLevelEmergency */
      ;
    default:
      ASSERT_UNREACHABLE("Bad log level");
      return 0; /* ASL_LEVEL_EMERG / kCFLogLevelEmergency */
      ;
  }
}

static void out_nslog_callback(const transport_log_message *const msg,
                               void *arg) {
  VAR_UNUSED(arg);
  *msg->p = 0;
  CFLog(apple_lvl(msg->lvl), CFSTR("%s"), msg->tag_b);
}

enum { OUT_NSLOG_MASK = TRANSPORT_LOG_PUT_STD & ~TRANSPORT_LOG_PUT_CTX };
#define OUT_NSLOG OUT_NSLOG_MASK, 0, out_nslog_callback
#endif

#if TRANSPORT_LOG_USE_DEBUGSTRING
#include <windows.h>

static void out_debugstring_callback(const transport_log_message *const msg,
                                     void *arg) {
  VAR_UNUSED(arg);
  msg->p[0] = '\n';
  msg->p[1] = '\0';
  OutputDebugStringA(msg->buf);
}

enum { OUT_DEBUGSTRING_MASK = TRANSPORT_LOG_PUT_STD };
#define OUT_DEBUGSTRING OUT_DEBUGSTRING_MASK, 0, out_debugstring_callback
#endif

void transport_log_out_stderr_callback(const transport_log_message *const msg,
                                       void *arg) {
  VAR_UNUSED(arg);
  const size_t eol_len = sizeof(TRANSPORT_LOG_EOL) - 1;
  memcpy(msg->p, TRANSPORT_LOG_EOL, eol_len);
#if defined(_WIN32) || defined(_WIN64)
  /* WriteFile() is atomic for local files opened with FILE_APPEND_DATA and
     without FILE_WRITE_DATA */
  DWORD written;
  WriteFile(GetStdHandle(STD_ERROR_HANDLE), msg->buf,
            (DWORD)(msg->p - msg->buf + eol_len), &written, 0);
#else
  /* write() is atomic for buffers less than or equal to PIPE_BUF. */
  RETVAL_UNUSED(
      write(STDERR_FILENO, msg->buf, (size_t)(msg->p - msg->buf) + eol_len));
#endif
}

static const transport_log_output out_stderr = {TRANSPORT_LOG_OUT_STDERR};

#if !TRANSPORT_LOG_EXTERN_TAG_PREFIX
TRANSPORT_LOG_DEFINE_TAG_PREFIX = 0;
#endif

#if !TRANSPORT_LOG_EXTERN_GLOBAL_FORMAT
TRANSPORT_LOG_DEFINE_GLOBAL_FORMAT = {TRANSPORT_LOG_MEM_WIDTH};
#endif

#if !TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT
#if TRANSPORT_LOG_USE_ANDROID_LOG
TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT = {OUT_ANDROID};
#elif TRANSPORT_LOG_USE_NSLOG
TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT = {OUT_NSLOG};
#elif TRANSPORT_LOG_USE_DEBUGSTRING
TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT = {OUT_DEBUGSTRING};
#else
TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT = {TRANSPORT_LOG_OUT_STDERR};
#endif
#endif

#if !TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL
TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT_LEVEL = 0;
#endif

const transport_log_spec _transport_log_stderr_spec = {
    TRANSPORT_LOG_GLOBAL_FORMAT,
    &out_stderr,
};

static const transport_log_spec global_spec = {
    TRANSPORT_LOG_GLOBAL_FORMAT,
    TRANSPORT_LOG_GLOBAL_OUTPUT,
};

#if _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(LEVEL, \
                                           TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
static char lvl_char(const int lvl) {
  switch (lvl) {
    case TRANSPORT_LOG_VERBOSE:
      return 'V';
    case TRANSPORT_LOG_DEBUG:
      return 'D';
    case TRANSPORT_LOG_INFO:
      return 'I';
    case TRANSPORT_LOG_WARN:
      return 'W';
    case TRANSPORT_LOG_ERROR:
      return 'E';
    case TRANSPORT_LOG_FATAL:
      return 'F';
    default:
      ASSERT_UNREACHABLE("Bad log level");
      return '?';
  }
}
#endif

#define GCCVER_LESS(MAJOR, MINOR, PATCH)                                  \
  (__GNUC__ < MAJOR || (__GNUC__ == MAJOR && (__GNUC_MINOR__ < MINOR ||   \
                                              (__GNUC_MINOR__ == MINOR && \
                                               __GNUC_PATCHLEVEL__ < PATCH))))

#if !defined(__clang__) && defined(__GNUC__) && GCCVER_LESS(4, 7, 0)
#define __atomic_load_n(vp, model) __sync_fetch_and_add(vp, 0)
#define __atomic_fetch_add(vp, n, model) __sync_fetch_and_add(vp, n)
#define __atomic_sub_fetch(vp, n, model) __sync_sub_and_fetch(vp, n)
#define __atomic_or_fetch(vp, n, model) __sync_or_and_fetch(vp, n)
#define __atomic_and_fetch(vp, n, model) __sync_and_and_fetch(vp, n)
/* Note: will not store old value of *vp in *ep (non-standard behaviour) */
#define __atomic_compare_exchange_n(vp, ep, d, weak, smodel, fmodel) \
  __sync_bool_compare_and_swap(vp, *(ep), d)
#endif

#if !TRANSPORT_LOG_OPTIMIZE_SIZE && !defined(_WIN32) && !defined(_WIN64)
#define TCACHE
#define TCACHE_STALE (0x40000000)
#define TCACHE_FLUID (0x40000000 | 0x80000000)
static unsigned g_tcache_mode = TCACHE_STALE;
static struct timeval g_tcache_tv = {0, 0};
static struct tm g_tcache_tm = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static INLINE int tcache_get(const struct timeval *const tv,
                             struct tm *const tm) {
  unsigned mode;
  mode = __atomic_load_n(&g_tcache_mode, __ATOMIC_RELAXED);
  if (0 == (mode & TCACHE_FLUID)) {
    mode = __atomic_fetch_add(&g_tcache_mode, 1, __ATOMIC_ACQUIRE);
    if (0 == (mode & TCACHE_FLUID)) {
      if (g_tcache_tv.tv_sec == tv->tv_sec) {
        *tm = g_tcache_tm;
        __atomic_sub_fetch(&g_tcache_mode, 1, __ATOMIC_RELEASE);
        return !0;
      }
      __atomic_or_fetch(&g_tcache_mode, TCACHE_STALE, __ATOMIC_RELAXED);
    }
    __atomic_sub_fetch(&g_tcache_mode, 1, __ATOMIC_RELEASE);
  }
  return 0;
}

static INLINE void tcache_set(const struct timeval *const tv,
                              struct tm *const tm) {
  unsigned stale = TCACHE_STALE;
  if (__atomic_compare_exchange_n(&g_tcache_mode, &stale, TCACHE_FLUID, 0,
                                  __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
    g_tcache_tv = *tv;
    g_tcache_tm = *tm;
    __atomic_and_fetch(&g_tcache_mode, ~TCACHE_FLUID, __ATOMIC_RELEASE);
  }
}
#endif

static void time_callback(struct tm *const tm, unsigned *const msec) {
#if !_TRANSPORT_LOG_MESSAGE_FORMAT_DATETIME_USED
  VAR_UNUSED(tm);
  VAR_UNUSED(msec);
#else
#if defined(_WIN32) || defined(_WIN64)
  SYSTEMTIME st;
  GetLocalTime(&st);
  tm->tm_year = st.wYear;
  tm->tm_mon = st.wMonth - 1;
  tm->tm_mday = st.wDay;
  tm->tm_wday = st.wDayOfWeek;
  tm->tm_hour = st.wHour;
  tm->tm_min = st.wMinute;
  tm->tm_sec = st.wSecond;
  *msec = st.wMilliseconds;
#else
  struct timeval tv;
  gettimeofday(&tv, 0);
#ifndef TCACHE
  localtime_r(&tv.tv_sec, tm);
#else
  if (!tcache_get(&tv, tm)) {
    localtime_r(&tv.tv_sec, tm);
    tcache_set(&tv, tm);
  }
#endif
  *msec = (unsigned)tv.tv_usec / 1000;
#endif
#endif
}

static void pid_callback(int *const pid, int *const tid) {
#if !_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(PID, \
                                            TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
  VAR_UNUSED(pid);
#else
#if defined(_WIN32) || defined(_WIN64)
  *pid = GetCurrentProcessId();
#else
  *pid = getpid();
#endif
#endif

#if !_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(TID, \
                                            TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
  VAR_UNUSED(tid);
#else
#if defined(_WIN32) || defined(_WIN64)
  *tid = GetCurrentThreadId();
#elif defined(__ANDROID__)
  *tid = gettid();
#elif defined(__linux__)
  *tid = syscall(SYS_gettid);
#elif defined(__MACH__)
  *tid = (int)pthread_mach_thread_np(pthread_self());
#else
#define Platform not supported
#endif
#endif
}

static void buffer_callback(transport_log_message *msg, char *buf) {
  msg->e = (msg->p = msg->buf = buf) + g_buf_sz;
}

#if _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(FUNCTION, \
                                           TRANSPORT_LOG_MESSAGE_SRC_FORMAT)
static const char *funcname(const char *func) { return func ? func : ""; }
#endif

#if _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(FILENAME, \
                                           TRANSPORT_LOG_MESSAGE_SRC_FORMAT)
static const char *filename(const char *file) {
  const char *f = file;
  for (const char *p = file; 0 != *p; ++p) {
    if ('/' == *p || '\\' == *p) {
      f = p + 1;
    }
  }
  return f;
}
#endif

static INLINE size_t nprintf_size(transport_log_message *const msg) {
  // *nprintf() always puts 0 in the end when input buffer is not empty. This
  // 0 is not desired because its presence sets (ctx->p) to (ctx->e - 1) which
  // leaves space for one more character. Some put_xxx() functions don't use
  // *nprintf() and could use that last character. In that case log line will
  // have multiple (two) half-written parts which is confusing. To workaround
  // that we allow *nprintf() to write its 0 in the eol area (which is always
  // not empty).
  return (size_t)(msg->e - msg->p + 1);
}

static INLINE void put_nprintf(transport_log_message *const msg, const int n) {
  if (0 < n) {
    msg->p = n < msg->e - msg->p ? msg->p + n : msg->e;
  }
}

static INLINE char *put_padding_r(const unsigned w, const char wc, char *p,
                                  char *e) {
  for (char *const b = e - w; b < p; *--p = wc) {
  }
  return p;
}

static char *put_integer_r(unsigned v, const int sign, const unsigned w,
                           const char wc, char *const e) {
  static const char _signs[] = {'-', '0', '+'};
  static const char *const signs = _signs + 1;
  char *p = e;
  do {
    *--p = '0' + v % 10;
  } while (0 != (v /= 10));
  if (0 == sign) return put_padding_r(w, wc, p, e);
  if ('0' != wc) {
    *--p = signs[sign];
    return put_padding_r(w, wc, p, e);
  }
  p = put_padding_r(w, wc, p, e + 1);
  *--p = signs[sign];
  return p;
}

static INLINE char *put_uint_r(const unsigned v, const unsigned w,
                               const char wc, char *const e) {
  return put_integer_r(v, 0, w, wc, e);
}

static INLINE char *put_int_r(const int v, const unsigned w, const char wc,
                              char *const e) {
  return 0 <= v ? put_integer_r((unsigned)v, 0, w, wc, e)
                : put_integer_r((unsigned)-v, -1, w, wc, e);
}

static INLINE char *put_stringn(const char *const s_p, const char *const s_e,
                                char *const p, char *const e) {
  const ptrdiff_t m = e - p;
  ptrdiff_t n = s_e - s_p;
  if (n > m) {
    n = m;
  }
  memcpy(p, s_p, n);
  return p + n;
}

static INLINE char *put_string(const char *s, char *p, char *const e) {
  const ptrdiff_t n = e - p;
  char *const c = (char *)memccpy(p, s, '\0', n);
  return 0 != c ? c - 1 : e;
}

static INLINE char *put_uint(unsigned v, const unsigned w, const char wc,
                             char *const p, char *const e) {
  char buf[16];
  char *const se = buf + _countof(buf);
  char *sp = put_uint_r(v, w, wc, se);
  return put_stringn(sp, se, p, e);
}

#define PUT_CSTR_R(p, STR)                         \
  do {                                             \
    for (unsigned i = sizeof(STR) - 1; 0 < i--;) { \
      *--(p) = (STR)[i];                           \
    }                                              \
  }                                                \
  _TRANSPORT_LOG_ONCE

#define PUT_CSTR_CHECKED(p, e, STR)                                 \
  do {                                                              \
    for (unsigned i = 0; (e) > (p) && (sizeof(STR) - 1) > i; ++i) { \
      *(p)++ = (STR)[i];                                            \
    }                                                               \
  }                                                                 \
  _TRANSPORT_LOG_ONCE

/* F_INIT field support.
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__YEAR
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__MONTH
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__DAY
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__HOUR
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__MINUTE
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__SECOND
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__MILLISECOND
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__PID
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__TID
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__LEVEL
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__TAG(ps, ts)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__FUNCTION
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__FILENAME
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__FILELINE
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__S(s)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__F_INIT(expr) _PP_UNTUPLE(expr);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT__F_UINT(w, v)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_INIT(field) \
  _PP_CONCAT_3(_TRANSPORT_LOG_MESSAGE_FORMAT_INIT_, _, field)

/* Implements generation of printf-like format string for log message
 * format specification.
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__ ""
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__YEAR "%04u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__MONTH "%02u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__DAY "%02u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__HOUR "%02u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__MINUTE "%02u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__SECOND "%02u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__MILLISECOND "%03u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__PID "%5i"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__TID "%5i"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__LEVEL "%c"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__TAG UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__FUNCTION "%s"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__FILENAME "%s"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__FILELINE "%u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__S(s) s
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__F_INIT(expr) ""
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT__F_UINT(w, v) "%" #w "u"
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT(field) \
  _PP_CONCAT_3(_TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT_, _, field)

/* Implements generation of printf-like format parameters for log message
 * format specification.
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__YEAR \
  , (unsigned)(tm.tm_year + 1900)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__MONTH \
  , (unsigned)(tm.tm_mon + 1)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__DAY , (unsigned)tm.tm_mday
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__HOUR , (unsigned)tm.tm_hour
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__MINUTE , (unsigned)tm.tm_min
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__SECOND , (unsigned)tm.tm_sec
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__MILLISECOND , (unsigned)msec
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__PID , pid
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__TID , tid
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__LEVEL \
  , (char)lvl_char(msg->lvl)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__TAG UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__FUNCTION , funcname(src->func)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__FILENAME , filename(src->file)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__FILELINE , src->line
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__S(s)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__F_INIT(expr)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL__F_UINT(w, v) , v
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL(field) \
  _PP_CONCAT_3(_TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL_, _, field)

/* Implements generation of put_xxx_t statements for log message specification.
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__YEAR \
  p = put_uint_r(tm.tm_year + 1900, 4, '0', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__MONTH \
  p = put_uint_r((unsigned)tm.tm_mon + 1, 2, '0', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__DAY \
  p = put_uint_r((unsigned)tm.tm_mday, 2, '0', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__HOUR \
  p = put_uint_r((unsigned)tm.tm_hour, 2, '0', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__MINUTE \
  p = put_uint_r((unsigned)tm.tm_min, 2, '0', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__SECOND \
  p = put_uint_r((unsigned)tm.tm_sec, 2, '0', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__MILLISECOND \
  p = put_uint_r(msec, 3, '0', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__PID p = put_int_r(pid, 5, ' ', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__TID p = put_int_r(tid, 5, ' ', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__LEVEL *--p = lvl_char(msg->lvl);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__TAG UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__FUNCTION UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__FILENAME UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__FILELINE UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__S(s) PUT_CSTR_R(p, s);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__F_INIT(expr)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R__F_UINT(w, v) \
  p = put_uint_r(v, w, ' ', p);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R(field) \
  _PP_CONCAT_3(_TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R_, _, field)

static void put_ctx(transport_log_message *const msg) {
  _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_INIT, TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
#if !_TRANSPORT_LOG_MESSAGE_FORMAT_FIELDS(TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
  VAR_UNUSED(msg);
#else
#if _TRANSPORT_LOG_MESSAGE_FORMAT_DATETIME_USED
  struct tm tm;
  unsigned msec;
  g_time_cb(&tm, &msec);
#endif
#if _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(     \
    PID, TRANSPORT_LOG_MESSAGE_CTX_FORMAT) ||   \
    _TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(TID, \
                                           TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
  int pid, tid;
  g_pid_cb(&pid, &tid);
#endif

#if TRANSPORT_LOG_OPTIMIZE_SIZE
  int n;
  n = snprintf(msg->p, nprintf_size(msg),
               _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT,
                       TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
                   _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL,
                           TRANSPORT_LOG_MESSAGE_CTX_FORMAT));
  put_nprintf(msg, n);
#else
  char buf[64];
  char *const e = buf + sizeof(buf);
  char *p = e;
  _PP_RMAP(_TRANSPORT_LOG_MESSAGE_FORMAT_PUT_R,
           TRANSPORT_LOG_MESSAGE_CTX_FORMAT)
  msg->p = put_stringn(p, e, msg->p, msg->e);
#endif
#endif
}

#define PUT_TAG(msg, tag, prefix_delim, tag_delim)                       \
  do {                                                                   \
    const char *ch;                                                      \
    msg->tag_b = msg->p;                                                 \
    if (0 != (ch = _transport_log_tag_prefix)) {                         \
      for (; msg->e != msg->p && 0 != (*msg->p = *ch); ++msg->p, ++ch) { \
      }                                                                  \
    }                                                                    \
    if (0 != (ch = tag) && 0 != tag[0]) {                                \
      if (msg->tag_b != msg->p) {                                        \
        PUT_CSTR_CHECKED(msg->p, msg->e, prefix_delim);                  \
      }                                                                  \
      for (; msg->e != msg->p && 0 != (*msg->p = *ch); ++msg->p, ++ch) { \
      }                                                                  \
    }                                                                    \
    msg->tag_e = msg->p;                                                 \
    if (msg->tag_b != msg->p) {                                          \
      PUT_CSTR_CHECKED(msg->p, msg->e, tag_delim);                       \
    }                                                                    \
  }                                                                      \
  _TRANSPORT_LOG_ONCE

/* Implements simple put statements for log message specification.
 */
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__YEAR UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__MONTH UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__DAY UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__HOUR UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__MINUTE UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__SECOND UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__MILLISECOND UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__PID UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__TID UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__LEVEL UNDEFINED
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__TAG(pd, td) \
  PUT_TAG(msg, tag, pd, td);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__FUNCTION \
  msg->p = put_string(funcname(src->func), msg->p, msg->e);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__FILENAME \
  msg->p = put_string(filename(src->file), msg->p, msg->e);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__FILELINE \
  msg->p = put_uint(src->line, 0, '\0', msg->p, msg->e);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__S(s) \
  PUT_CSTR_CHECKED(msg->p, msg->e, s);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__F_INIT(expr)
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT__F_UINT(w, v) \
  msg->p = put_uint(v, w, ' ', msg->p, msg->e);
#define _TRANSPORT_LOG_MESSAGE_FORMAT_PUT(field) \
  _PP_CONCAT_3(_TRANSPORT_LOG_MESSAGE_FORMAT_PUT_, _, field)

static void put_tag(transport_log_message *const msg, const char *const tag) {
  _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_INIT, TRANSPORT_LOG_MESSAGE_TAG_FORMAT)
#if !_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(TAG, \
                                            TRANSPORT_LOG_MESSAGE_TAG_FORMAT)
  VAR_UNUSED(tag);
#endif
#if !_TRANSPORT_LOG_MESSAGE_FORMAT_FIELDS(TRANSPORT_LOG_MESSAGE_TAG_FORMAT)
  VAR_UNUSED(msg);
#else
  _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_PUT, TRANSPORT_LOG_MESSAGE_TAG_FORMAT)
#endif
}

static void put_src(transport_log_message *const msg,
                    const src_location *const src) {
  _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_INIT, TRANSPORT_LOG_MESSAGE_SRC_FORMAT)
#if !_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(           \
    FUNCTION, TRANSPORT_LOG_MESSAGE_SRC_FORMAT) &&     \
    !_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(           \
        FILENAME, TRANSPORT_LOG_MESSAGE_SRC_FORMAT) && \
    !_TRANSPORT_LOG_MESSAGE_FORMAT_CONTAINS(FILELINE,  \
                                            TRANSPORT_LOG_MESSAGE_SRC_FORMAT)
  VAR_UNUSED(src);
#endif
#if !_TRANSPORT_LOG_MESSAGE_FORMAT_FIELDS(TRANSPORT_LOG_MESSAGE_SRC_FORMAT)
  VAR_UNUSED(msg);
#else
#if TRANSPORT_LOG_OPTIMIZE_SIZE
  int n;
  n = snprintf(msg->p, nprintf_size(msg),
               _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_FMT,
                       TRANSPORT_LOG_MESSAGE_SRC_FORMAT)
                   _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_PRINTF_VAL,
                           TRANSPORT_LOG_MESSAGE_SRC_FORMAT));
  put_nprintf(msg, n);
#else
  _PP_MAP(_TRANSPORT_LOG_MESSAGE_FORMAT_PUT, TRANSPORT_LOG_MESSAGE_SRC_FORMAT)
#endif
#endif
}

static void put_msg(transport_log_message *const msg, const char *const fmt,
                    va_list va) {
  int n;
  msg->msg_b = msg->p;
  n = vsnprintf(msg->p, nprintf_size(msg), fmt, va);
  put_nprintf(msg, n);
}

static void output_mem(const transport_log_spec *log,
                       transport_log_message *const msg,
                       const mem_block *const mem) {
  if (0 == mem->d || 0 == mem->d_sz) {
    return;
  }
  const unsigned char *mem_p = (const unsigned char *)mem->d;
  const unsigned char *const mem_e = mem_p + mem->d_sz;
  const unsigned char *mem_cut;
  const ptrdiff_t mem_width = (ptrdiff_t)log->format->mem_width;
  char *const hex_b = msg->msg_b;
  char *const ascii_b = hex_b + 2 * mem_width + 2;
  char *const ascii_e = ascii_b + mem_width;
  if (msg->e < ascii_e) {
    return;
  }
  while (mem_p != mem_e) {
    char *hex = hex_b;
    char *ascii = ascii_b;
    for (mem_cut = mem_width < mem_e - mem_p ? mem_p + mem_width : mem_e;
         mem_cut != mem_p; ++mem_p) {
      const unsigned char ch = *mem_p;
      *hex++ = c_hex[(0xf0 & ch) >> 4];
      *hex++ = c_hex[(0x0f & ch)];
      *ascii++ = isprint(ch) ? (char)ch : '?';
    }
    while (hex != ascii_b) {
      *hex++ = ' ';
    }
    msg->p = ascii;
    log->output->callback(msg, log->output->arg);
  }
}

void transport_log_set_tag_prefix(const char *const prefix) {
  _transport_log_tag_prefix = prefix;
}

void transport_log_set_mem_width(const unsigned w) {
  _transport_log_global_format.mem_width = w;
}

void transport_log_set_output_level(const int lvl) {
  _transport_log_global_output_lvl = lvl;
}

void transport_log_set_output_v(const unsigned mask, void *const arg,
                                const transport_log_output_cb callback) {
  _transport_log_global_output.mask = mask;
  _transport_log_global_output.arg = arg;
  _transport_log_global_output.callback = callback;
}

static void _transport_log_write_imp(const transport_log_spec *log,
                                     const src_location *const src,
                                     const mem_block *const mem, const int lvl,
                                     const char *const tag,
                                     const char *const fmt, va_list va) {
  transport_log_message msg;
  char buf[TRANSPORT_LOG_BUF_SZ];
  const unsigned mask = log->output->mask;
  msg.lvl = lvl;
  msg.tag = tag;
  g_buffer_cb(&msg, buf);
  if (TRANSPORT_LOG_PUT_CTX & mask) {
    put_ctx(&msg);
  }
  if (TRANSPORT_LOG_PUT_TAG & mask) {
    put_tag(&msg, tag);
  }
  if (0 != src && TRANSPORT_LOG_PUT_SRC & mask) {
    put_src(&msg, src);
  }
  if (TRANSPORT_LOG_PUT_MSG & mask) {
    put_msg(&msg, fmt, va);
  }
  log->output->callback(&msg, log->output->arg);
  if (0 != mem && TRANSPORT_LOG_PUT_MSG & mask) {
    output_mem(log, &msg, mem);
  }
}

void _transport_log_write_d(const char *const func, const char *const file,
                            const unsigned line, const int lvl,
                            const char *const tag, const char *const fmt, ...) {
  const src_location src = {func, file, line};
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(&global_spec, &src, 0, lvl, tag, fmt, va);
  va_end(va);
}

void _transport_log_write_aux_d(const char *const func, const char *const file,
                                const unsigned line,
                                const transport_log_spec *const log,
                                const int lvl, const char *const tag,
                                const char *const fmt, ...) {
  const src_location src = {func, file, line};
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(log, &src, 0, lvl, tag, fmt, va);
  va_end(va);
}

void _transport_log_write(const int lvl, const char *const tag,
                          const char *const fmt, ...) {
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(&global_spec, 0, 0, lvl, tag, fmt, va);
  va_end(va);
}

void _transport_log_write_aux(const transport_log_spec *const log,
                              const int lvl, const char *const tag,
                              const char *const fmt, ...) {
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(log, 0, 0, lvl, tag, fmt, va);
  va_end(va);
}

void _transport_log_write_mem_d(const char *const func, const char *const file,
                                const unsigned line, const int lvl,
                                const char *const tag, const void *const d,
                                const unsigned d_sz, const char *const fmt,
                                ...) {
  const src_location src = {func, file, line};
  const mem_block mem = {d, d_sz};
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(&global_spec, &src, &mem, lvl, tag, fmt, va);
  va_end(va);
}

void _transport_log_write_mem_aux_d(const char *const func,
                                    const char *const file, const unsigned line,
                                    const transport_log_spec *const log,
                                    const int lvl, const char *const tag,
                                    const void *const d, const unsigned d_sz,
                                    const char *const fmt, ...) {
  const src_location src = {func, file, line};
  const mem_block mem = {d, d_sz};
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(log, &src, &mem, lvl, tag, fmt, va);
  va_end(va);
}

void _transport_log_write_mem(const int lvl, const char *const tag,
                              const void *const d, const unsigned d_sz,
                              const char *const fmt, ...) {
  const mem_block mem = {d, d_sz};
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(&global_spec, 0, &mem, lvl, tag, fmt, va);
  va_end(va);
}

void _transport_log_write_mem_aux(const transport_log_spec *const log,
                                  const int lvl, const char *const tag,
                                  const void *const d, const unsigned d_sz,
                                  const char *const fmt, ...) {
  const mem_block mem = {d, d_sz};
  va_list va;
  va_start(va, fmt);
  _transport_log_write_imp(log, 0, &mem, lvl, tag, fmt, va);
  va_end(va);
}