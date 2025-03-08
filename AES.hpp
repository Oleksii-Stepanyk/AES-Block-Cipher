#pragma once

class AES {
    static constexpr int Nb = 4;
    int Nk;
    int Nr;

public:
    explicit AES(const int keySize) {
        switch (keySize) {
        case 16:
            Nk = 4;
            Nr = 10;
            break;
        case 24:
            Nk = 6;
            Nr = 12;
            break;
        case 32:
            Nk = 8;
            Nr = 14;
            break;
        }
    }
};
