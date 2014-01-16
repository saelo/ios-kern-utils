#
# iOS toolchain information.
#
# Adapt this file for your system.
#

SET(CMAKE_SYSTEM_NAME iOS)

# specify the cross compiler
SET(CMAKE_C_COMPILER   /opt/ios-toolchain/bin/ios-clang)
SET(CMAKE_CXX_COMPILER /opt/ios-toolchain/bin/ios-clang++)

# where is the target environment
SET(CMAKE_FIND_ROOT_PATH /opt/ios-toolchain/share/iPhoneOS6.0.sdk)

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
