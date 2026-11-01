cmake_minimum_required(VERSION 3.5)
project (kptools)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
# Keep host kptools ABI structs identical to the embedded kpimg core.
# Use quote-only search: never shadow libc's <stdint.h> with kernel/include/stdint.h.

set(SOURCES
	image.c
	kallsym.c
	kptools.c
	order.c
	insn.c
	patch.c
	symbol.c
	kpm.c
	common.c
	x86_64.c
)

add_executable(
	kptools 
	${SOURCES}
)
target_compile_options(kptools PRIVATE "-iquote${CMAKE_CURRENT_SOURCE_DIR}/../kernel/include")

find_package(ZLIB REQUIRED)
	
target_link_libraries(kptools PRIVATE ${ZLIB_LIBRARIES})
	
target_include_directories(kptools PRIVATE ${ZLIB_INCLUDE_DIRS})