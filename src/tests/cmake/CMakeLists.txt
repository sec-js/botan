cmake_minimum_required(VERSION 3.20)

project(Botan_CMake_Tests CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED On)
set(CMAKE_CXX_EXTENSIONS Off)

# tell CMake where to find BotanConfig.cmake and BotanConfigVersion.cmake
set(Botan_DIR ../../../build)

# test #1: find any Botan version
find_package(Botan)
if(NOT Botan_FOUND)
  message(FATAL_ERROR "Test #1 failed: Failed to find Botan with any version")
endif()

add_executable(botan_version_test main.cpp)
target_link_libraries(botan_version_test Botan::Botan)

# clean up variables defined by BotanConfig.cmake
unset(Botan_INCLUDE_DIRS)
unset(Botan_LIBRARIES)
unset(Botan_FOUND)

# test #2: find Botan version installed by version number
find_package(Botan ${Botan_VERSION})
if(NOT Botan_FOUND)
  message(FATAL_ERROR "Failed to find Botan with version ${Botan_VERSION}")
endif()

unset(Botan_INCLUDE_DIRS)
unset(Botan_LIBRARIES)
unset(Botan_FOUND)

# test #3: find Botan with specific modules
find_package(Botan ${Botan_VERSION} COMPONENTS ecdsa rsa)
if(NOT Botan_FOUND)
  message(FATAL_ERROR "Failed to find Botan with version ${Botan_VERSION} containing modules: ecdsa, rsa")
endif()

unset(Botan_INCLUDE_DIRS)
unset(Botan_LIBRARIES)
unset(Botan_FOUND)

# test #4: fail if required module is not included
find_package(Botan ${Botan_VERSION} COMPONENTS tpm)
if(Botan_FOUND)
  message(FATAL_ERROR "Found Botan with version ${Botan_VERSION}: Found module tpm but expected it to be absent")
endif()

unset(Botan_INCLUDE_DIRS)
unset(Botan_LIBRARIES)
unset(Botan_FOUND)
