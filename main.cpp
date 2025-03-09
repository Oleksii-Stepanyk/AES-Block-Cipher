#include <iostream>
#include "AES-ECB.hpp"
#include "AES-CBC.hpp"
#include "AES-CFB.hpp"

int main() {
    AES_ECB ecb(16);
    AES_CBC cbc(16);
    AES_CFB cfb(16);
    const unsigned char input[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const unsigned char* cipher_ecb = ecb.Encrypt(input, key);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(cipher_ecb[i]) << " ";
    }
    std::cout << std::endl;

    const unsigned char* result_ecb = ecb.Decrypt(cipher_ecb, key);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(result_ecb[i]) << " ";
    }
    std::cout << std::endl;

    const unsigned char* cipher_cbc = cbc.Encrypt(input, key, iv);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(cipher_cbc[i]) << " ";
    }
    std::cout << std::endl;

    const unsigned char* result_cbc = cbc.Decrypt(cipher_cbc, key, iv);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(result_cbc[i]) << " ";
    }
    std::cout << std::endl;

    const unsigned char* cipher_cfb = cfb.Encrypt(input, key, iv);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(cipher_cfb[i]) << " ";
    }
    std::cout << std::endl;

    const unsigned char* result_cfb = cfb.Decrypt(cipher_cfb, key, iv);
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(result_cfb[i]) << " ";
    }
    std::cout << std::endl;
    return 0;
}
