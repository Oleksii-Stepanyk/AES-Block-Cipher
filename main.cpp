#include <iostream>
#include "AES-ECB.hpp"
#include "AES-CBC.hpp"
#include "AES-CFB.hpp"

int main() {
    // Init AES modes
    AES_ECB ecb(16);
    AES_CBC cbc(16);
    AES_CFB cfb(16);

    // Init input, iv and key
    constexpr int inputSize = 64;

    const unsigned char input[64] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
        0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
        0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
        0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    };

    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Print input, iv and key
    std::cout << "Input: ";
    for (const unsigned char i : input) {
        std::cout << std::hex << static_cast<int>(i) << " ";
    }
    std::cout << std::endl;

    std::cout << "Initialization vector: ";
    for (const unsigned char i : iv) {
        std::cout << std::hex << static_cast<int>(i) << " ";
    }
    std::cout << std::endl;

    std::cout << "Key: ";
    for (const unsigned char i : key) {
        std::cout << std::hex << static_cast<int>(i) << " ";
    }
    std::cout << std::endl;
    std::cout << std::endl;
    // ECB start
    const unsigned char* cipher_ecb = ecb.Encrypt(input, key, inputSize);
    for (int i = 0; i < inputSize; i++) {
        std::cout << std::hex << static_cast<int>(cipher_ecb[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    const unsigned char* result_ecb = ecb.Decrypt(cipher_ecb, key, inputSize);
    for (int i = 0; i < inputSize; i++) {
        std::cout << std::hex << static_cast<int>(result_ecb[i]) << " ";
    }
    std::cout << std::endl << std::endl;
    // ECB end
    // CBC start
    const unsigned char* cipher_cbc = cbc.Encrypt(input, key, iv, inputSize);
    for (int i = 0; i < inputSize; i++) {
        std::cout << std::hex << static_cast<int>(cipher_cbc[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    const unsigned char* result_cbc = cbc.Decrypt(cipher_cbc, key, iv, inputSize);
    for (int i = 0; i < inputSize; i++) {
        std::cout << std::hex << static_cast<int>(result_cbc[i]) << " ";
    }
    std::cout << std::endl << std::endl;
    // CBC end
    // CFB start
    const unsigned char* cipher_cfb = cfb.Encrypt(input, key, iv, inputSize);
    for (int i = 0; i < inputSize; i++) {
        std::cout << std::hex << static_cast<int>(cipher_cfb[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    const unsigned char* result_cfb = cfb.Decrypt(cipher_cfb, key, iv, inputSize);
    for (int i = 0; i < inputSize; i++) {
        std::cout << std::hex << static_cast<int>(result_cfb[i]) << " ";
    }
    std::cout << std::endl << std::endl;
    // CFB end

    delete[] cipher_ecb;
    delete[] result_ecb;
    delete[] cipher_cbc;
    delete[] result_cbc;
    delete[] cipher_cfb;
    delete[] result_cfb;

    return 0;
}
