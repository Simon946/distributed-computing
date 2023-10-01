#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include "aes.cpp"

using namespace AES;

void printArray(uint8_t* in, size_t size){
    std::cout << std::hex;
    for(size_t i = 0; i < size; i++){
        std::cout << (int)in[i];
    }
    std::cout << std::dec << std::endl;
}

void printCandT(uint8_t* in, size_t size){
    std::cout << "ciphertext: ";
    printArray(in, size - blockSizeBytes);
    std::cout << "authentication tag ";
    printArray(in + size - 16, 16);

}



bool compare(uint8_t* lhs, uint8_t* rhs, size_t size){
    for(size_t i = 0; i < size; i++){
        if(lhs[i] != rhs[i]){
            return false;
        }
    }
    return true;
}

uint8_t hexTo4bit(unsigned char hex){
    std::vector<int> convertTable = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };
    int value = convertTable.at((int)hex);

    if (value == -1) throw std::invalid_argument("invalid hex digit");
    return value;
}

uint8_t* hexToBytes(std::string hex){
    uint8_t* result = new uint8_t[hex.size() / 2];
    
    for(int i = 0; i < hex.size(); i += 2){
        uint8_t upper = hexTo4bit(hex.at(i));
        uint8_t lower = hexTo4bit(hex.at(i + 1));
        result[i / 2] = (upper << 4) | lower;
    }   
    return result;
}


bool test1(){
    //input
    uint8_t K[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //Key, 128bits
    uint8_t IV[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //initialization vector/nonce, 128bits
    uint8_t* P = nullptr; //plaintext, aka unencrypted input, 0 bits
    uint8_t* A = nullptr; //additional data to authenticate but not encrypt, aka AAD, 0 bits

    //output
    uint8_t output[16]; //C, ciphertext, aka encrypted plaintext, same lenght as P
    uint8_t* T = output + 0; //authentication tag is at output + sizeof P
    uint8_t expectedT[] = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
    encrypt(P, 0, output, 16, K, 16, IV, 16);
    printArray(output, 16);

    return compare(T, expectedT, 16);
}

bool test2(){
    uint8_t K[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //Key, 128bits
    uint8_t IV[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //initialization vector/nonce, 128bits
    uint8_t P[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};; //plaintext, aka unencrypted input, 0 bits
    uint8_t* A = nullptr; //additional data to authenticate but not encrypt, aka AAD, 0 bits

        //output
    uint8_t output[32]; //C, ciphertext, aka encrypted plaintext, same lenght as P
    uint8_t* T = output + 16; //authentication tag is at output + sizeof P
    uint8_t expectedT[] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    uint8_t expectedC[] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    encrypt(P, 16, output, 32, K, 16, IV, 16);
    printCandT(output, 32);

    return compare(T, expectedT, 16);

}

bool test3(){
    uint8_t K[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}; //Key, 128bits

    

    uint8_t* P = hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    size_t Psize = 4 * 16;

    uint8_t* IV = hexToBytes("cafebabefacedbaddecaf88800000000");
    
    uint8_t* A = nullptr; //additional data to authenticate but not encrypt, aka AAD, 0 bits

        //output
    uint8_t output[Psize + 16]; //C, ciphertext, aka encrypted plaintext, same lenght as P
    uint8_t* T = output + Psize; //authentication tag is at output + sizeof P
    uint8_t* expectedT = hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4");
    uint8_t* expectedC = hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
    encrypt(P, Psize, output, Psize + 16, K, 16, IV, 16);
    printCandT(output, Psize + 16);

    return compare(T, expectedT, 16) && compare(output, expectedC, Psize);
}

bool test4(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test5(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test6(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test7(){
    uint8_t* K = hexToBytes("000000000000000000000000000000000000000000000000");
    uint8_t* IV = hexToBytes("00000000000000000000000000000000");
    uint8_t* expectedT = hexToBytes("cd33b28ac773f74ba00ed1f312572435");
    uint8_t T[16];
    encrypt(nullptr, 0, T, 16, K, 24, IV, 16);
    return compare(expectedT, T, 16);
}

bool test8(){
    uint8_t* K = hexToBytes("000000000000000000000000000000000000000000000000");
    uint8_t* IV = hexToBytes("00000000000000000000000000000000");
    uint8_t* P = hexToBytes("00000000000000000000000000000000");
    uint8_t* expectedT = hexToBytes("2ff58d80033927ab8ef4d4587514f0fb");
    uint8_t* expectedC = hexToBytes("98e7247c07f0fe411c267e4384b0f600");
    uint8_t output[32];
    encrypt(P, 16, output, 32, K, 24, IV, 16);
    return compare(expectedT, output + 16, 16) && compare(expectedC, output, 16);
}

bool test9(){
    uint8_t* K = hexToBytes("feffe9928665731c6d6a8f9467308308feffe9928665731c");
    uint8_t* P = hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    uint8_t* IV = hexToBytes("cafebabefacedbaddecaf88800000000");

    uint8_t output[16 * 4 + 16];
    uint8_t* expectedT = hexToBytes("9924a7c8587336bfb118024db8674a14");
    uint8_t* expectedC = hexToBytes("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256");
    encrypt(P, 4 * 16, output, 5 * 16, K, 24, IV, 16);
    printCandT(output, 5 * 16);
    return compare(expectedT, output + 16 * 4, 16) && compare(expectedC, output, 16 * 4);
}

bool test10(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test11(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test12(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test13(){

    uint8_t* K = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    uint8_t* IV = hexToBytes("00000000000000000000000000000000");
    uint8_t* P = nullptr;
    uint8_t* expectedT = hexToBytes("530f8afbc74536b9a963b4f1c4cb738b");
    uint8_t* expectedC = nullptr;
    uint8_t output[16];
    encrypt(P, 0, output, 16, K, 32, IV, 16);
    return compare(expectedT, output, 16);
}

bool test14(){
    uint8_t* K = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    uint8_t* IV = hexToBytes("00000000000000000000000000000000");
    uint8_t* P = hexToBytes("00000000000000000000000000000000");;
    uint8_t* expectedT = hexToBytes("d0d1c8a799996bf0265b98b5d48ab919");
    uint8_t* expectedC = hexToBytes("cea7403d4d606b6e074ec5d3baf39d18");
    uint8_t output[32];
    encrypt(P, 16, output, 32, K, 32, IV, 16);
    return compare(expectedT, output + 16, 16) && compare(expectedC, output, 16);
}

bool test15(){
    uint8_t* K = hexToBytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    uint8_t* IV = hexToBytes("cafebabefacedbaddecaf88800000000");
    uint8_t* P = hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    uint8_t* expectedT = hexToBytes("b094dac5d93471bdec1a502270e3cc6c");
    uint8_t* expectedC = hexToBytes("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
    size_t Psize = 4 * 16;
    uint8_t output[Psize + 16];
    encrypt(P, Psize, output, Psize + 16, K, 32, IV, 16);
    return compare(expectedT, output + Psize, 16) && compare(expectedC, output, Psize);
}

bool test16(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test17(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}

bool test18(){
    std::cout << "unencrypted additional data not supported" << std::endl;
    return true;
}
int main(){
    std::cout << "starting tests..." << std::endl;


    assert(test1());
    assert(test2());
    assert(test3());
    assert(test4());
    assert(test5());
    assert(test6());
    assert(test7());
    assert(test8());
    assert(test9());
    assert(test10());
    assert(test11());
    assert(test12());
    assert(test13());
    assert(test14());
    assert(test15());

    return 0;
}