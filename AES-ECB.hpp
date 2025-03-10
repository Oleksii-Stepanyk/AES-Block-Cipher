#pragma once
#include <cstring>
#include <stdexcept>

#include "AES.hpp"

class AES_ECB final : public AES {
public:
    explicit AES_ECB(const int keySize): AES(keySize) {
    }

    ~AES_ECB() override = default;

    const unsigned char* Encrypt(const unsigned char* input, const unsigned char* key, const int inputSize) {
        const int paddingSize = 16 - inputSize % 16;
        const auto temp = AddPadding(input, inputSize);
        const auto result = new unsigned char[inputSize + paddingSize];
        const int blocks = (inputSize + paddingSize) / 16;
        for (int i = 0; i < blocks; i++) {
            const unsigned char* block = EncryptBlock(temp + i * 16, key);
            memcpy(result + i * 16, block, 16);
            delete[] block;
        }
        delete[] temp;
        return result;
    }

    const unsigned char* Decrypt(const unsigned char* input, const unsigned char* key, const int inputSize) {
        const int paddingSize = 16 - inputSize % 16;
        const auto result = new unsigned char[inputSize + paddingSize];
        const int blocks = (inputSize + paddingSize) / 16;
        for (int i = 0; i < blocks; i++) {
            const unsigned char* block = DecryptBlock(input + i * 16, key);
            memcpy(result + i * 16, block, 16);
            delete[] block;
        }
        const auto temp = RemovePadding(result, inputSize);
        memcpy(result, temp, inputSize);
        delete[] temp;
        return result;
    }
};
