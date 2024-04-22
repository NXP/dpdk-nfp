set(ENV{PKG_CONFIG_PATH} ${DPDK_INSTALL}/lib/pkgconfig)
find_package(PkgConfig REQUIRED)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(DPDK REQUIRED "libdpdk")
	if (DPDK_FOUND)
		message(STATUS "found dpdk via pkt-config")
	endif()
	add_definitions(${DPDK_STATIC_CFLAGS})
	include_directories(${DPDK_INCLUDE_DIRS})
	include_directories(${DPDK_INSTALL}/share/dpdk/examples/common/)
	link_libraries(${DPDK_STATIC_LDFLAGS})
endif()

AUX_SOURCE_DIRECTORY(. SRC_LIST)

ADD_LIBRARY(nfp SHARED ${SRC_LIST})

ADD_LIBRARY(nfp_static STATIC ${SRC_LIST})
SET_TARGET_PROPERTIES(nfp_static PROPERTIES OUTPUT_NAME "nfp")
