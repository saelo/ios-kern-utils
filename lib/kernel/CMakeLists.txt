file (GLOB C_FILES *.c)

add_library(kernel STATIC ${C_FILES})
# see toolchain-ios.cmake
add_custom_command(TARGET kernel
    POST_BUILD
    COMMAND ${RANLIB_PATH} "${PROJECT_BINARY_DIR}/lib/kernel/libkernel.a")
