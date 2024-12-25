#include "salsa.h"

const int KEYLENGTH = 32;
const int IVLENGTH = 8;

// hex: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
CryptoPP::byte key[KEYLENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
// hex: B0B1B2B3B4B5B6B7
CryptoPP::byte iv[IVLENGTH] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7};



class EncHandler {
private:
    CryptoPP::Salsa20::Encryption enc;
    CryptoPP::Salsa20::Encryption dec;
public:
  EncHandler(CryptoPP::byte key[], CryptoPP::byte iv[]) {
    // set key and iv
    enc.SetKeyWithIV(key, KEYLENGTH, iv, IVLENGTH);
    dec.SetKeyWithIV(key, KEYLENGTH, iv, IVLENGTH);
  }

  void encrypt(const char *plainText, CryptoPP::byte *outBuffer) {
    // encrypt plainText
    enc.ProcessData(outBuffer, (const CryptoPP::byte *) plainText, strlen(plainText));
  }

  void decrypt(char *cipherText, char *outBuffer) {
    // decrypt cipherText
    dec.ProcessData((CryptoPP::byte *) cipherText, (const CryptoPP::byte *) cipherText, strlen(cipherText));
  }
};
