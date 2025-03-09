#pragma once
#include <cstring>
#include <stdexcept>

#include "AES.hpp"

class AES_CBC final : public AES {
public:
    explicit AES_CBC(const int keySize): AES(keySize) {
    }

    ~AES_CBC() override = default;

    const unsigned char* Encrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv) {
        const int inputSize = strlen(reinterpret_cast<const char*>(input));

        const auto result = new unsigned char[inputSize];
        auto* xorData = new unsigned char[16];
        const int blocks = inputSize / 16;

        memcpy(xorData, iv, 16);
        for (int i = 0; i < blocks; ++i) {
            const unsigned char* xoredBlock = XorBlocks(input + i * 16, xorData);
            const unsigned char* encryptedBlock = EncryptBlock(xoredBlock, key);
            memcpy(xorData, encryptedBlock, 16);
            memcpy(result + i * 16, encryptedBlock, 16);
            delete[] xoredBlock;
            delete[] encryptedBlock;
        }

        delete[] xorData;
        return result;
    }

    const unsigned char* Decrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv) {
        const int inputSize = strlen(reinterpret_cast<const char*>(input));

        const auto result = new unsigned char[inputSize];
        unsigned char* xorData = new unsigned char[16];
        const int blocks = inputSize / 16;

        memcpy(xorData, iv, 16);
        for (int i = 0; i < blocks; ++i) {
            const unsigned char* decryptedBlock = DecryptBlock(input + i * 16, key);
            const unsigned char* xoredBlock = XorBlocks(decryptedBlock, xorData);
            memcpy(xorData, input + i * 16, 16);
            memcpy(result + i * 16, xoredBlock, 16);
            delete[] decryptedBlock;
            delete[] xoredBlock;
        }
        delete[] xorData;
        return result;
    }
};
