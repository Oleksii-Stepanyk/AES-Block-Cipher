cmake_minimum_required(VERSION 3.29)
project(AES_Block_Cipher)

set(CMAKE_CXX_STANDARD 20)

# Main executable
add_executable(AES_Block_Cipher main.cpp
        AES.hpp
        AES-ECB.hpp
        AES-CBC.hpp
        AES-CFB.hpp)

# Separate executable for the attacks
add_executable(AES_CBC_Padding_Oracle_Attack AES-CBC_Padding_Oracle_Attack.cpp
        AES-CBC.hpp
        AES.hpp)

add_executable(AES-CFB_Bit_Flipping_Attack AES-CFB_Bit_Flipping_Attack.cpp
        AES-CFB.hpp
        AES.hpp)