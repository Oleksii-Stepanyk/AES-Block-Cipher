#pragma once
#include <cstring>
#include <stdexcept>

#include "AES.hpp"

class AES_ECB final : public AES {
public:
    explicit AES_ECB(const int keySize): AES(keySize) {}

    ~AES_ECB() override = default;

    const unsigned char* Encrypt(const unsigned char* input, const unsigned char* key, const int inputSize) {
        const auto result = new unsigned char[inputSize];
        const int blocks = inputSize / 16;
        for (int i = 0; i < blocks; i++) {
            const unsigned char* block = EncryptBlock(input + i * 16, key);
            memcpy(result + i * 16, block, 16);
            delete[] block;
        }
        return result;
    }

    const unsigned char* Decrypt(const unsigned char* input, const unsigned char* key, const int inputSize) {
        const auto result = new unsigned char[inputSize];
        const int blocks = inputSize / 16;
        for (int i = 0; i < blocks; i++) {
            const unsigned char* block = DecryptBlock(input + i * 16, key);
            memcpy(result + i * 16, block, 16);
            delete[] block;
        }
        return result;
    }
};
