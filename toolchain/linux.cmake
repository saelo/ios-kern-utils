#
# iOS toolchain information.
#
# Adapt this file for your system.
#

set(CMAKE_SYSTEM_NAME iOS)

# specify the cross compiler
set(CMAKE_C_COMPILER   /opt/ios-toolchain/bin/ios-clang)
set(CMAKE_CXX_COMPILER /opt/ios-toolchain/bin/ios-clang++)

# set path to cross compiler ranlib tool
#
# This shouldn't have to be set, I'm assuming cmake
# fails to detect the ar/ranlib executable from the iOS
# toolchain... Hopefully there is a better fix for this
set(RANLIB_PATH /opt/ios-toolchain/bin/arm-apple-darwin11-ranlib)

# where is the target environment
set(CMAKE_FIND_ROOT_PATH /opt/ios-toolchain/share/iPhoneOS6.0.sdk)

# search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
