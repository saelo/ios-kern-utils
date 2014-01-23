# set target architecture, possible values: armv7, armv6 or arm64
set(IOS_TARGET_ARCH arm64)
# set SDK path, should be ok on default installation
set(CMAKE_IOS_SDK_ROOT /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.0.sdk)
# set path of ranlib tool
set(RANLIB_PATH /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ranlib)



set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_FIND_ROOT_PATH ${CMAKE_IOS_SDK_ROOT})
set(__CMAKE_C_COMPILER_ARG1_VAL "-arch ${IOS_TARGET_ARCH} -isysroot ${CMAKE_IOS_SDK_ROOT}")
set(CMAKE_C_COMPILER_ARG1 ${__CMAKE_C_COMPILER_ARG1_VAL})
set(CMAKE_CXX_COMPILER_ARG1 ${__CMAKE_C_COMPILER_ARG1_VAL})
