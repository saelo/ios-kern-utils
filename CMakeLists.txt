# set cross compiler options
set(CMAKE_TOOLCHAIN_FILE toolchain-ios.cmake)

cmake_minimum_required (VERSION 2.6)
project (iOS-Kernel-Utilities)

# need ldid to sign the binaries and add the entitlements
find_program(LDIDTool ldid)
if(LDIDTool MATCHES ".*NOTFOUND")
    message(FATAL_ERROR "ldid not found, make sure it is installed and in $PATH")
endif()

include_directories("${PROJECT_SOURCE_DIR}/libkern")
add_subdirectory(libkern)

set(TOOLS kdump kmap)
foreach(tool ${TOOLS})
    message("preparing ${tool}")
    add_executable (${tool} ${tool}/${tool}.c)
    target_link_libraries(${tool} kern)
    add_custom_command(TARGET ${tool}
                POST_BUILD
                COMMAND ${LDIDTool} "-S${PROJECT_SOURCE_DIR}/misc/ent.xml" ${tool})
endforeach(tool)
