cmake_minimum_required(VERSION 3.14)

project(crypto LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)
find_package(libsecp256k1)
find_package(Boost REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})

add_library(
  Crypto STATIC
  qaesencryption.cpp
  qaesencryption.h
  instr.h
  meta_random.h
  obfuscator.h
  Inline.h
  MetaFSM.h
  MetaString.h
  ObfuscatedCallWithPredicate.h
  Indexes.h
  Log.h
  MetaRandom.h
  ObfuscatedCall.h
  Unroller.h
  secp256k1s.h
  secp256k1s.cpp)

target_link_libraries(Crypto PRIVATE Qt${QT_VERSION_MAJOR}::Core
                                     libsecp256k1::secp256k1 ${Boost_LIBRARIES})

target_compile_definitions(Crypto PRIVATE CRYPTO_LIBRARY)
