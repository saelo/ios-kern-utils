
#set your arch here or ext armv7, armv6 or arm64
set(IOS_TARGET_ARCH arm64)
#set your SDK by should be ok on default instalation
set(CMAKE_IOS_SDK_ROOT /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.0.sdk)
#set your RANLIB 
set(RANLIB_PATH /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ranlib)



set(CMAKE_C_COMPILER clang) 
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_FIND_ROOT_PATH ${CMAKE_IOS_SDK_ROOT})
set(__CMAKE_C_COMPILER_ARG1_VAL "-arch ${IOS_TARGET_ARCH} -isysroot ${CMAKE_IOS_SDK_ROOT}")
set(CMAKE_C_COMPILER_ARG1 ${__CMAKE_C_COMPILER_ARG1_VAL})
set(CMAKE_CXX_COMPILER_ARG1 ${__CMAKE_C_COMPILER_ARG1_VAL})
