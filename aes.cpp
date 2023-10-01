#include <iostream>
#include <vector>
#include <immintrin.h>//for aes instructions
//compile with: g++ -o aes aes.cpp -maes -mavx2 -O3 -msse2 -mpclmul
namespace AES {
    const int blockSizeBytes = 128 / 8; //= 16 bytes per block

    const std::vector<uint8_t> sBox = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

    const std::vector<uint32_t> roundConstants= {//round 0 has no constant, used for expandKey
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
    };

    #define cpuid(func,ax,bx,cx,dx)\
    __asm__ __volatile__ ("cpuid":\
        "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));
    
    bool checkCPUSupport(){
        unsigned int a,b,c,d;
        cpuid(1, a,b,c,d);
        return (c & 0x2000000) == 0x2000000;
    }

    uint8_t substitute8(uint8_t value){
        return sBox.at(value);
    }

    uint32_t substitute32(uint32_t value){
        return (substitute8((value >> 24) & 0xFF) << 24) | (substitute8((value >> 16) & 0xFF) << 16) | (substitute8((value >> 8) & 0xFF) << 8) | (substitute8((value) & 0xFF));
    }

    std::vector<uint8_t> separateBytes(const std::vector<uint32_t>& input){
        std::vector<uint8_t> result;
        result.resize(4 * input.size());
        for(int i = 0; i < input.size(); i++){
            uint32_t tmp = input.at(i);

            for(int j = 3; j >= 0; j--){
                result.at(4*i + j) =(tmp & 0xFF);
                tmp >>= 8;
            }
        }
        return result;
    }
    
    std::vector<uint32_t> mergeBytes(const std::vector<uint8_t>& input){
        std::vector<uint32_t> result;
        uint32_t tmp = 0;
        result.resize(input.size() / 4);

        for(int i = 0; i < input.size(); i++){
            uint8_t fraction = input.at(i);
            
            tmp <<= 8;
            tmp |= fraction;

            if(i % 4 == 3){
                result.at(i / 4) = tmp;
            }
        }
        result.back() = tmp;
        return result;
    }

    __m128i loadFrom8vector(const std::vector<uint8_t>& data){
        uint8_t bytes[blockSizeBytes];
        
        for(int i = 0; i < blockSizeBytes; i++){
            bytes[i] = data.at(i);
        }
        return _mm_loadu_si128((__m128i*)bytes);
    }

    __m128i loadFrom32vector(const std::vector<uint32_t>& data){
        return loadFrom8vector(separateBytes(data));
    }

    void print(__m128i block){

        uint8_t bytes[16];
        _mm_storeu_si128((__m128i*)bytes, block);
        std::cout << std::hex;
        for(int i = 0; i < 16; i++){
            std::cout << (int)bytes[i];
        }
        std::cout << std::endl << std::dec;
    }
    bool equal(__m128i lhs, __m128i rhs){
        __m128i neq = _mm_xor_si128(lhs, rhs);
      return _mm_test_all_zeros(neq, neq);
    }

    const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i multGF128(__m128i lhs, __m128i rhs){//this function is not understandable but very fast
	__m128i temp1, temp2, temp3, temp4, temp5, temp6;
	lhs = _mm_shuffle_epi8(lhs, MASK);
	rhs = _mm_shuffle_epi8(rhs, MASK);

	temp1 = _mm_clmulepi64_si128(lhs, rhs, 0x00);
	temp2 = _mm_clmulepi64_si128(lhs, rhs, 0x01);
	temp3 = _mm_clmulepi64_si128(lhs, rhs, 0x10);
	temp4 = _mm_clmulepi64_si128(lhs, rhs, 0x11);

	temp2 = _mm_xor_si128(temp2, temp3);
	temp3 = _mm_slli_si128(temp2, 8);
	temp2 = _mm_srli_si128(temp2, 8);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp4 = _mm_xor_si128(temp4, temp2);

	temp5 = _mm_srli_epi32(temp1, 31);
	temp1 = _mm_slli_epi32(temp1, 1);

	temp6 = _mm_srli_epi32(temp4, 31);
	temp4 = _mm_slli_epi32(temp4, 1);

	temp3 = _mm_srli_si128(temp5, 12);
	temp6 = _mm_slli_si128(temp6, 4);
	temp5 = _mm_slli_si128(temp5, 4);
	temp1 = _mm_or_si128(temp1, temp5);
	temp4 = _mm_or_si128(temp4, temp6);
	temp4 = _mm_or_si128(temp4, temp3);

	temp5 = _mm_slli_epi32(temp1, 31);
	temp6 = _mm_slli_epi32(temp1, 30);
	temp3 = _mm_slli_epi32(temp1, 25);

	temp5 = _mm_xor_si128(temp5, temp6);
	temp5 = _mm_xor_si128(temp5, temp3);
	temp6 = _mm_srli_si128(temp5, 4);
	temp4 = _mm_xor_si128(temp4, temp6);
	temp5 = _mm_slli_si128(temp5, 12);
	temp1 = _mm_xor_si128(temp1, temp5);
	temp4 = _mm_xor_si128(temp4, temp1);

	temp5 = _mm_srli_epi32(temp1, 1);
	temp2 = _mm_srli_epi32(temp1, 2);
	temp3 = _mm_srli_epi32(temp1, 7);
	temp4 = _mm_xor_si128(temp4, temp2);
	temp4 = _mm_xor_si128(temp4, temp3);
	temp4 = _mm_xor_si128(temp4, temp5);

	return _mm_shuffle_epi8(temp4, MASK);
}

    std::vector<std::vector<__m128i>> createLookUptables(__m128i block){//uses 256 * 16 * 16 bytes.
        std::vector<std::vector<__m128i>> lookUpTables;
        lookUpTables.reserve(blockSizeBytes);
        
        for(int i = 0; i < blockSizeBytes; i++){
            std::vector<__m128i> table;
            table.resize(256);
            std::vector<uint8_t>bytes(blockSizeBytes, 0);
            
            for(int j = 0; j < table.size(); j++){
                __m128i tmp = loadFrom8vector(bytes);
                table.at(j) = multGF128(block, tmp);
                bytes.at(i)++;
            }
            lookUpTables.push_back(table);
        }
        return lookUpTables;
    }

    __m128i multGF128fast(__m128i block, const std::vector<std::vector<__m128i>>& lookupTables){ //this is only faster for about 220 or more multiplications of the same block.
        __m128i result; 

        if(lookupTables.size() != blockSizeBytes){
            throw std::invalid_argument("wrong lookup tables");
        }
        uint8_t bytes[blockSizeBytes];
        _mm_storeu_si128((__m128i*) &bytes, block);

        for(int i = 0; i < blockSizeBytes; i++){
            result = _mm_xor_si128(result, lookupTables.at(i).at(bytes[i]));
        }
        return result;
    }

    const __m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
    void add(__m128i& block, uint32_t value){
        block = _mm_shuffle_epi8(block, BSWAP_EPI64);
        __m128i valueBlock = _mm_set_epi32(0,value,0,0);
        block = _mm_add_epi64(block, valueBlock);
        block = _mm_shuffle_epi8(block, BSWAP_EPI64);
    }
    uint32_t rotate32(uint32_t value){
        return (value << 8) | ((value >> 24) & 0xFF);
    }

    std::vector<__m128i> expandKey(const std::vector<uint32_t>& key) {
        //source https://en.wikipedia.org/wiki/AES_key_schedule
        int numberOfRounds = 0;

        switch (key.size())
        {
        case 4:{
            numberOfRounds = 11;
            break;
        }
        case 6:{
            numberOfRounds = 13;
            break;
        }
        case 8:{
            numberOfRounds = 15;
            break;
        }
        default:
            throw std::invalid_argument("key size must be 128, 192 or 256 bits\n");
            break;
        }

        int expandedKeySize = 4 * numberOfRounds;
        int oldKeySize = key.size();
        std::vector<uint32_t>expandedKey = key;
        expandedKey.resize(expandedKeySize);

        for(int i = oldKeySize; i < expandedKeySize; i++){
            expandedKey.at(i) ^= expandedKey.at(i - oldKeySize);

            if (i % oldKeySize == 0) {
                expandedKey.at(i) ^= substitute32(rotate32(expandedKey.at(i - 1))) ^ roundConstants.at(i / oldKeySize);
            }
            else if(oldKeySize > 6 && i % oldKeySize == 4){
                expandedKey.at(i) ^= substitute32(expandedKey.at(i - 1));
            }
            else{
                expandedKey.at(i) ^= expandedKey.at(i - 1);
            }
        }
        std::vector<__m128i> result;
        
        for(int i = 0; i < expandedKey.size(); i+=4){
            result.push_back(loadFrom32vector(std::vector<uint32_t>(expandedKey.begin() + i, expandedKey.begin() + i + 4)));
        }
        return result;
    }

    inline __m128i encrypt(const __m128i& block, const std::vector<__m128i>& roundKeys){
        __m128i encryptedBlock = block ^ roundKeys.at(0);//TODO make this fast.
        
        for(int round = 1; round < roundKeys.size() -1; round++){
            encryptedBlock = _mm_aesenc_si128(encryptedBlock, roundKeys.at(round));
        }
        return _mm_aesenclast_si128(encryptedBlock, (__m128i)roundKeys.back());
    }  
   
    size_t encrypt(uint8_t* in, size_t inSize, uint8_t* out, size_t outSize, uint8_t* key, size_t keySize, uint8_t* nonce, size_t nonceSize){//returns the size in bytes of the output.
        std::vector<uint8_t> keyBytes;

        if(outSize - (outSize % blockSizeBytes) < inSize){
            throw std::invalid_argument("the outSize is too small\n");
        }
        if(nonceSize != blockSizeBytes){
            throw std::invalid_argument("the nonce should be the size of a block\n");
        }
        if(keySize != 16 && keySize != 24 && keySize != 32){
            throw std::invalid_argument("The key has to be 128, 192 or 256 bits\n");
        }
        if(!checkCPUSupport()){
            throw std::invalid_argument("The cpu does not support AES instructions\n");
        }
        if(inSize % blockSizeBytes != 0){
             throw std::invalid_argument("the inputSize should be the size of n blocks\n");
        }
        for(int i = 0; i < keySize; i++){
            keyBytes.push_back(key[i]);
        }
        const std::vector<__m128i> roundKeys = expandKey(mergeBytes(keyBytes));
        const __m128i hash = encrypt(_mm_setzero_si128(), roundKeys);

        const std::vector<std::vector<__m128i>> hashLookUpTable = createLookUptables(hash);
        __m128i authenticationTag = _mm_setzero_si128();
        __m128i IV = _mm_loadu_si128((__m128i*)nonce);
        add(IV, 1);

        size_t i = 0;

        for(i = 0; i < inSize; i += blockSizeBytes){
            add(IV, 1);
            __m128i currentBlock = _mm_loadu_si128((__m128i*)(in + i)) ^ encrypt(IV, roundKeys);//encrypt is slow
            _mm_storeu_si128((__m128i*)(out + i), currentBlock);
            authenticationTag = multGF128((currentBlock ^ authenticationTag), hash);
        }
        
        __m128i resultLength = _mm_setzero_si128();
        add(resultLength, 8 * inSize);
        authenticationTag = multGF128((authenticationTag ^ resultLength), hash);

        __m128i nonceBlock = _mm_loadu_si128((__m128i*)nonce);  
        add(nonceBlock, 1);
        authenticationTag = authenticationTag ^ encrypt(nonceBlock, roundKeys);
        _mm_storeu_si128((__m128i*)(out + i), authenticationTag);
        return i + blockSizeBytes;
    }

    size_t decrypt(uint8_t* in, size_t inSize, uint8_t* out, size_t outSize, uint8_t* key, size_t keySize, uint8_t* nonce, size_t nonceSize){//returns the size in bytes of the output.
        std::vector<uint8_t> keyBytes;

        if(outSize - (outSize % blockSizeBytes) < (inSize - blockSizeBytes)){
            throw std::invalid_argument("the outSize is too small\n");
        }
        if(nonceSize != blockSizeBytes){
            throw std::invalid_argument("the nonce should be the size of a block\n");
        }
        if(keySize % 16 != 0){
            throw std::invalid_argument("The key has to be 128, 192 or 256 bits\n");
        }
        if(!checkCPUSupport()){
            throw std::invalid_argument("The cpu does not support AES instructions\n");
        }
        for(int i = 0; i < keySize; i++){
            keyBytes.push_back(key[i]);
        }
        std::vector<__m128i> roundKeys = expandKey(mergeBytes(keyBytes));

        const __m128i hash = encrypt(_mm_setzero_si128(), roundKeys);
        const std::vector<std::vector<__m128i>> hashLookUpTable = createLookUptables(hash);
        __m128i authenticationTag = _mm_setzero_si128();
        __m128i resultLength = _mm_setzero_si128();
        __m128i IV =  _mm_loadu_si128((__m128i*)nonce);//initialization vector
        size_t i = 0;

        for(i = 0; i < inSize - blockSizeBytes; i += blockSizeBytes){
            add(IV, 1);
            __m128i currentBlock = _mm_loadu_si128((__m128i*)(in + i)) ^ encrypt(IV, roundKeys);
            _mm_storeu_si128((__m128i*)(out + i), currentBlock);
            authenticationTag = multGF128fast((authenticationTag ^ _mm_loadu_si128((__m128i*)(in + i))), hashLookUpTable);
        }
        add(resultLength, i / blockSizeBytes);

        authenticationTag = multGF128fast((authenticationTag ^ resultLength), hashLookUpTable);
        authenticationTag ^= encrypt(_mm_loadu_si128((__m128i*)nonce), roundKeys);

        if(!equal(authenticationTag,_mm_loadu_si128((__m128i*)(in + i)))){
            std::cout << "invalid authenticationtag" << std::endl;
            std::cout << "calculated tag: ";
            print(authenticationTag);
            std::cout << "found tag: ";
            print(_mm_loadu_si128((__m128i*)(in + i)));
            return 0;
        }
        else{
            std::cout << "ok, tag matches" << std::endl;
        }
        return i - blockSizeBytes;
    }
    //TODO make inline decrypt function to decrypt from a starting point and ignore authtag.
}
