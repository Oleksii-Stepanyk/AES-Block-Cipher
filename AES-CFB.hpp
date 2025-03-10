#pragma once
#include <cstring>
#include <stdexcept>

#include "AES.hpp"

class AES_CFB final : public AES {
public:
    explicit AES_CFB(const int keySize): AES(keySize) {
    }

    ~AES_CFB() override = default;

    const unsigned char* Encrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv, const int inputSize) {
        AddPadding(input, inputSize);
        const int paddingSize = 16 - inputSize % 16;
        const auto result = new unsigned char[inputSize + paddingSize];
        const auto xorData = new unsigned char[16];
        const int blocks = (inputSize + paddingSize) / 16;

        memcpy(xorData, iv, 16);
        for (int i = 0; i < blocks; i++) {
            const unsigned char* block = EncryptBlock(xorData, key);
            const unsigned char* xoredBlock = XorBlocks(input + i * 16, block);
            memcpy(result + i * 16, xoredBlock, 16);
            memcpy(xorData, xoredBlock, 16);
            delete[] xoredBlock;
            delete[] block;
        }
        return result;
    }

    const unsigned char* Decrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv, const int inputSize) {
        const int paddingSize = 16 - inputSize % 16;
        const auto result = new unsigned char[inputSize + paddingSize];
        const auto xorData = new unsigned char[16];
        const int blocks = (inputSize + paddingSize) / 16;

        memcpy(xorData, iv, 16);
        for (int i = 0; i < blocks; i++) {
            const unsigned char* block = EncryptBlock(xorData, key);
            const unsigned char* xoredBlock = XorBlocks(input + i * 16, block);
            memcpy(xorData, input + i * 16, 16);
            memcpy(result + i * 16, xoredBlock, 16);
            delete[] xoredBlock;
            delete[] block;
        }
        RemovePadding(result, inputSize);
        return result;
    }
};
