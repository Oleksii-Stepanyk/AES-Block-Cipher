#include <iostream>
#include <string>
#include <stdexcept>
#include <cstring>
#include "AES-CBC.hpp"

using namespace std;

extern const int kBytesInBlock;
extern vector<unsigned char> keyVec;
extern vector<unsigned char> iVec;

void PaddingOracleCBC(unsigned char* ctData, long long int ctSize, AES_CBC& aes)
{
    unsigned char* modCtData = new unsigned char[ctSize];
    memcpy(modCtData, ctData, ctSize);

    long long int blockStart = ctSize - 2LL * kBytesInBlock;
    long long int currentIdx = ctSize - 1 - kBytesInBlock;
    unsigned char padCount = 0;

    unsigned char* recoveredPlain = new unsigned char[kBytesInBlock];
    long long int recoveredIndex = kBytesInBlock - 1;

    for (; currentIdx >= blockStart && padCount < kBytesInBlock; --currentIdx)
    {
        bool byteRecovered = false;
        for (int trialValue = 0; trialValue < 256 && !byteRecovered; trialValue++)
        {
            modCtData[currentIdx] = static_cast<unsigned char>(trialValue);
            try {
                aes.Decrypt(modCtData, keyVec.data(), iVec.data(), kBytesInBlock);
                byteRecovered = true;
                padCount++;
                unsigned char recoveredByte = static_cast<unsigned char>(trialValue) ^ padCount ^ ctData[currentIdx];
                recoveredPlain[recoveredIndex] = recoveredByte;
                recoveredIndex--;
                for (long long int j = currentIdx; j < ctSize - kBytesInBlock; j++)
                {
                    modCtData[j] = ctData[j] ^ padCount ^ (padCount + 1);
                }
            } catch (const std::invalid_argument&) {
                // wrong padding -> next val
            }
        }
    }
    
    string recoveredText(reinterpret_cast<char*>(recoveredPlain + (kBytesInBlock - padCount)), padCount);
    cout << recoveredText;

    delete[] modCtData;
    delete[] recoveredPlain;
}
