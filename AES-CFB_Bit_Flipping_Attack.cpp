#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include "AES-CFB.hpp"

using namespace std;

const int kBytesInBlock = 16;

vector<unsigned char> keyVec = {
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
    0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};

vector<unsigned char> iVec = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

int main()
{
    cout << "Enter message: ";
    string input;
    getline(cin, input);
    if (input.empty())
    {
        cout << "Empty message!" << endl;
        return 1;
    }
    
    int msgLen = input.size();
    unsigned char* plainText = new unsigned char[msgLen];
    memcpy(plainText, input.c_str(), msgLen);
    
    AES_CFB aes(32);

    const unsigned char* cipherText = aes.Encrypt(plainText, keyVec.data(), iVec.data(), msgLen);

    unsigned char* modCipherText = new unsigned char[msgLen];
    memcpy(modCipherText, cipherText, msgLen);

    int targetIndex = 5;
    if (msgLen <= targetIndex)
        targetIndex = msgLen - 1;
    modCipherText[targetIndex] ^= 0x01;

    const unsigned char* attackedPlainText = aes.Decrypt(modCipherText, keyVec.data(), iVec.data(), msgLen);

    cout << "Modified plaintext: " << string(reinterpret_cast<const char*>(attackedPlainText), msgLen) << endl;

    delete[] plainText;
    delete[] const_cast<unsigned char*>(cipherText);
    delete[] modCipherText;
    delete[] const_cast<unsigned char*>(attackedPlainText);
    
    return 0;
}
