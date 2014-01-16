file (GLOB C_FILES *.c)

add_library(kern STATIC ${C_FILES})
# see toolchain-ios.cmake
add_custom_command(TARGET kern
    POST_BUILD
    COMMAND ${RANLIB_PATH} "${PROJECT_BINARY_DIR}/libkern/libkern.a")
