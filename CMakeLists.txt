# set cross compiler options
if(APPLE)
  set(CMAKE_TOOLCHAIN_FILE toolchain/mac.cmake)
else()
  set(CMAKE_TOOLCHAIN_FILE toolchain/linux.cmake)
endif()

cmake_minimum_required (VERSION 2.6)
project (iOS-Kernel-Utilities)

# need ldid to sign the binaries and add the entitlements
find_program(LDIDTool ldid)
if(LDIDTool MATCHES ".*NOTFOUND")
    message(FATAL_ERROR "ldid not found, make sure it is installed and in $PATH")
endif()

# build libraries
include_directories("${PROJECT_SOURCE_DIR}/lib/kernel")
include_directories("${PROJECT_SOURCE_DIR}/lib/binary")
add_subdirectory(lib/kernel)
add_subdirectory(lib/binary)

# build tools
set(TOOLS kdump kmap kmem kpatch)
foreach(tool ${TOOLS})
    message("preparing ${tool}")
    add_executable(${tool} tools/${tool}.c)
    target_link_libraries(${tool} kernel)
    add_custom_command(TARGET ${tool}
                POST_BUILD
                COMMAND ${LDIDTool} "-S${PROJECT_SOURCE_DIR}/misc/ent.xml" ${tool})
endforeach(tool)
