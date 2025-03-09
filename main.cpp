#include <iostream>
#include "AES.hpp"

int main() {
    AES aes(16);
    const unsigned char input[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    const unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const unsigned char* cipher = aes.Encrypt(input, key);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(cipher[i]) << " ";
    }
    std::cout << std::endl;
    const unsigned char* result = aes.Decrypt(cipher, key);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(result[i]) << " ";
    }
    std::cout << std::endl;
    return 0;
}
