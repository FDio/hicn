# Detect the cache size
#
# XXX: TODO: This is a bug when cross compiling. We are detecting the local
# Cache Line size and not the target cache line size.  We should provide some
# way to define this

set(LEVEL1_DCACHE_LINESIZE 32)

if( APPLE )
  execute_process(COMMAND sysctl -n hw.cachelinesize
	OUTPUT_VARIABLE LEVEL1_DCACHE_LINESIZE
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif( APPLE )

if( ${CMAKE_SYSTEM_NAME} STREQUAL "Linux" )
  execute_process(COMMAND getconf LEVEL1_DCACHE_LINESIZE
	OUTPUT_VARIABLE LEVEL1_DCACHE_LINESIZE
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

message(STATUS "Cache line size: ${LEVEL1_DCACHE_LINESIZE}")
