// helloworld

#include <iostream>

#include "salsa.h"
#include "base64.h"
#include "sample.h"

using namespace std;



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




int main() {
    cout << "Hello, World!" << endl;
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
