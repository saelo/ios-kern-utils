# file(GLOB C_FILES *.c)
set(C_FILES binary.c common.c find.c mach-o/binary.c mach-o/inject.c mach-o/link.c dyldcache/binary.c)
message(${C_FILES})

add_library(binary STATIC ${C_FILES})
# see toolchain-ios.cmake
add_custom_command(TARGET binary
    POST_BUILD
    COMMAND ${RANLIB_PATH} "${PROJECT_BINARY_DIR}/lib/binary/libbinary.a")
