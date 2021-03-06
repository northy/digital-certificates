cmake_minimum_required(VERSION 3.0)
project(digital-certificates CXX)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set (CMAKE_CXX_STANDARD 17)
set (LIBRESSL_INCLUDE_DIR "/usr/lib/libressl")

add_library(sources
  src/crypto.cpp
  src/file.cpp
)
include_directories(include)

find_package(LibreSSL REQUIRED)

add_subdirectory(libs/fire-hpp REQUIRED)

add_executable(Generate app/generate.cxx)
target_link_libraries(Generate
  sources
  fire-hpp::fire-hpp
  LibreSSL::Crypto
)

add_executable(Sign app/sign.cxx)
target_link_libraries(Sign
  sources
  fire-hpp::fire-hpp
  LibreSSL::Crypto
)

add_executable(Verify app/verify.cxx)
target_link_libraries(Verify
  sources
  fire-hpp::fire-hpp
  LibreSSL::Crypto
)

