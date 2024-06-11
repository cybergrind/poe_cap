// helloworld

#include <iostream>

#include "salsa.h"
#include "base64.h"

using namespace std;

const int KEYLENGTH = 32;
const int IVLENGTH = 8;


char plainText[] = "Hello, World!22";

char* b64enc(CryptoPP::byte *inBuffer, size_t size) {
  CryptoPP::Base64Encoder encoder;
  cout << "Length: " << size << endl;
  encoder.Put(inBuffer, size);
  encoder.MessageEnd();
  const int outSize = encoder.MaxRetrievable();
  cout << "OutSize: " << outSize << endl;
  // allocate on heap + terminate byte
  char *outBuffer = new char[outSize + 1];
  encoder.Get((CryptoPP::byte *) &outBuffer[0], outSize);
  outBuffer[outSize] = '\0';
  return outBuffer;
}

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

  void encrypt(char *plainText, CryptoPP::byte *outBuffer) {
    // encrypt plainText
    enc.ProcessData(outBuffer, (const CryptoPP::byte *) plainText, strlen(plainText));
  }

  void decrypt(char *cipherText, char *outBuffer) {
    // decrypt cipherText
    dec.ProcessData((CryptoPP::byte *) cipherText, (const CryptoPP::byte *) cipherText, strlen(cipherText));
  }
};




int main() {
    cout << "Hello, World!" << endl;
    // hex: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    CryptoPP::byte key[KEYLENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    // hex: B0B1B2B3B4B5B6B7
    CryptoPP::byte iv[IVLENGTH] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7};

    // allocate on heap
    EncHandler *enc = new EncHandler(key, iv);
    // subtract 1 for null terminator
    const int outBufferSize = sizeof(plainText)-1;
    CryptoPP::byte outBuffer[outBufferSize+1];

    //memset(outBuffer, 0, outBufferSize);
    enc->encrypt(plainText, outBuffer);
    cout << "RawEncrypted: " << outBuffer << endl;
    char* out = b64enc(outBuffer, outBufferSize);
    cout << "Encrypted: " << out << endl;
    delete[] out;

    cout << "Go with enc2" << endl;
    EncHandler *enc2 = new EncHandler(key, iv);
    char out2[outBufferSize+1];
    cout << "Perform decryption" << endl;
    enc2->decrypt((char *)outBuffer, out2);
    cout << "Decrypted: " << outBuffer << endl;
    return 0;
}
