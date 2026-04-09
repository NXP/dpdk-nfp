include(CheckSymbolExists)
set(ENV{PKG_CONFIG_PATH} ${DPDK_INSTALL}/lib/pkgconfig)
find_package(PkgConfig REQUIRED)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(DPDK REQUIRED "libdpdk")
	if (DPDK_FOUND)
		message(STATUS "found dpdk via pkt-config")
	endif()

	check_symbol_exists(RTE_NET_DPAA2
		  "rte_config.h"
		  HAS_DPAA2)
	if(HAS_DPAA2)
		message(STATUS "DPAA2 PMD enable")
		add_compile_definitions(RTE_NET_DPAA2)
	endif()
	add_definitions(${DPDK_STATIC_CFLAGS})
	include_directories(${DPDK_INCLUDE_DIRS})
	include_directories(${DPDK_INSTALL}/share/dpdk/examples/common/)
	link_libraries(${DPDK_STATIC_LDFLAGS})
endif()

AUX_SOURCE_DIRECTORY(. SRC_LIST)
AUX_SOURCE_DIRECTORY(pre_ld SRC_LIST)

ADD_LIBRARY(nfp SHARED ${SRC_LIST})

ADD_LIBRARY(nfp_static STATIC ${SRC_LIST})
SET_TARGET_PROPERTIES(nfp_static PROPERTIES OUTPUT_NAME "nfp")

find_package(Threads REQUIRED)

# Apply consistently to both
target_link_libraries(nfp PRIVATE Threads::Threads)
target_link_libraries(nfp_static PRIVATE Threads::Threads)

target_compile_definitions(nfp PRIVATE ENABLE_PRE_LD)
target_compile_definitions(nfp_static PRIVATE ENABLE_PRE_LD)
