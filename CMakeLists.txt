cmake_minimum_required(VERSION 3.29)
project(AES_Block_Cipher)

set(CMAKE_CXX_STANDARD 20)

add_executable(AES_Block_Cipher main.cpp
        AES.hpp
        AES-ECB.hpp
        AES-CBC.hpp
        AES-CFB.hpp)
