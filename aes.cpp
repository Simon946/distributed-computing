#include <iostream>
#include <vector>
#include <immintrin.h>//for aes instructions
//compile with: g++ -o aes aes.cpp -maes -mavx2
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
            if(i % 4 == 0){
                result.at(i / 4) = tmp;
            }
        }
        result.back() = tmp;
        return result;
    }

    class Block{
        public:
            Block(){
                valuesVector = _mm_setzero_si128();
            };
            Block(uint8_t* data);
            Block(const std::vector<uint8_t>& data);
            Block(const std::vector<uint32_t>& data);
            Block(__m128i data);
            Block encrypt(const std::vector<uint32_t>& key);
            Block encrypt(const std::vector<Block>& key);

            void print();

            void shiftRows();
            void mixColumns();
            Block multGF128(const Block& rhs) const;//multiply in Galois Field 2^128
            std::vector<std::vector<Block>> createLookUptables() const; //generate lookup tables for faster multiplication of this block
            Block multGF128fast(const std::vector<std::vector<Block>>& lookupTables);//this is only faster for about 220 or more multiplications of one block.

            void operator^=(const Block& rhs);
            void operator<<=(int value);
            void operator>>=(int value);
            void operator++(int prefixOrPostFix);

            bool operator == (const Block& rhs);
            bool operator != (const Block& rhs);

            Block operator & (const Block& rhs) const;
            Block operator ^ (const Block& rhs);
            Block operator >> (int value);
            Block operator << (int value);

            __m128i valuesVector;//public because of the saveBlocks function.
    };

    Block::Block(uint8_t* data){
        valuesVector = _mm_loadu_si128((__m128i*)data);
    }

    Block::Block(const std::vector<uint8_t>& data){
        uint8_t bytes[16];
        
        for(int i = 0; i < 16; i++){
            bytes[i] = data.at(i);
        }
        valuesVector = _mm_loadu_si128((__m128i*)bytes);
    }

    Block::Block(const std::vector<uint32_t>& data){
        std::vector<uint8_t> bytesVector = separateBytes(data);
        uint8_t bytes[16];
        
        for(int i = 0; i < 16; i++){
            bytes[i] = bytesVector.at(i);
        }
        valuesVector = _mm_loadu_si128((__m128i*)bytes);
    }

    Block::Block(__m128i data){
        valuesVector = data;
    }

    void Block::operator^=(const Block& rhs){
        *this = *this ^ rhs;
    }

    void Block::operator<<=(int value){
        *this = *this << value;
    }

    void Block::operator>>=(int value){
        *this = *this >> value;
    }

    void Block::operator++(int prefixOrPostFix){
        uint64_t v[2];
        _mm_store_si128((__m128i*)&v, valuesVector);
        uint64_t lower = v[0];
        v[0]++;
        if(lower > v[0]){
            v[1]++;
        }
        valuesVector = _mm_load_si128((const __m128i*)&v);
    }

    Block Block::operator ^ (const Block& rhs){
        return Block(_mm_xor_si128 (valuesVector, rhs.valuesVector));
    }

    Block Block::operator & (const Block& rhs) const{
        return Block(_mm_and_si128(valuesVector, rhs.valuesVector));
    }

    bool Block::operator == (const Block& rhs){
        __m128i neq = _mm_xor_si128(valuesVector, rhs.valuesVector);
      return _mm_test_all_zeros(neq,neq);
    }

    bool Block::operator != (const Block& rhs){
        return !(*this == rhs);
    }

    Block Block::operator >> (int value){

        if(value >= 8){
            return (*this >> 7) >> (value - 7);
        }
        uint8_t bytes[blockSizeBytes];
        uint8_t result[blockSizeBytes];
        _mm_storeu_si128((__m128i*) &bytes, this->valuesVector);

        result[0] = bytes[0] >> value;

        for(int i = 1; i < blockSizeBytes; i++){
            uint16_t tmp = bytes[i -1] << 8 | bytes[i];
            result[i] = (tmp >> value) & 0xFF;
        }
        return result;
    }

    Block Block::operator << (int value){        
        
        if(value >= 8){
            return (*this << 7) << (value - 7);
        }
        uint8_t bytes[blockSizeBytes];
        _mm_storeu_si128((__m128i*) &bytes, this->valuesVector);

        for(int i = 0; i < blockSizeBytes -1; i++){
            uint16_t tmp = (bytes[i] << 8) | bytes[i + 1];
            bytes[i] = ((tmp << value) >> 8) & 0xFF;
        }
        bytes[blockSizeBytes -1] = bytes[blockSizeBytes -1] << value;
        return Block(bytes);
    }

    Block Block::multGF128(const Block& rhs) const{//multiply in Galois Field 2^128 use multGF128fast for over 220 multiplications of the same block
        Block result;
        Block lhs = Block(*this);

        Block one = Block(std::vector<uint8_t>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}));
        Block zero;
        const Block R = Block(std::vector<uint8_t>({0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
        Block mask = Block(std::vector<uint8_t>({0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));

        for(int i = 0; i < 128; i++){

            if( (rhs & mask) != zero){
                result ^= lhs;
            }
            if((lhs & one) == zero){
                lhs >>= 1;
            }
            else {
                lhs = (lhs >> 1) ^ R;
            }
            mask >>= 1;
        }
        return result;
    }

    Block Block::multGF128fast(const std::vector<std::vector<Block>>& lookupTables){ //this is only faster for about 220 or more multiplications of the same block.
        Block result; 

        if(lookupTables.size() != blockSizeBytes){
            throw std::invalid_argument("wrong lookup tables");
        }
        uint8_t bytes[blockSizeBytes];
        _mm_storeu_si128((__m128i*) &bytes, this->valuesVector);

        for(int i = 0; i < blockSizeBytes; i++){
            result ^= lookupTables.at(i).at(bytes[i]);
        }
        return result;
    }

    std::vector<std::vector<Block>> Block::createLookUptables() const{//takes about 8.5 seconds and uses 256 * 16 * 16 bytes.
        std::vector<std::vector<Block>> lookUpTables;
        
        for(int i = 0; i < blockSizeBytes; i++){
            std::vector<Block> table;
            table.resize(256);
            std::vector<uint8_t>bytes(blockSizeBytes, 0);
            
            for(int j = 0; j < table.size(); j++){
                Block tmp = Block(bytes);
                table.at(j) = this->multGF128(tmp);
                bytes.at(i)++;
            }
            lookUpTables.push_back(table);
        }
        return lookUpTables;
    }

    void Block::print(){

        uint8_t bytes[16];
        _mm_storeu_si128((__m128i*)bytes, (__m128i)valuesVector);
        std::cout << std::hex;
        for(int i = 0; i < 16; i++){
            std::cout << (int)bytes[i];
        }
        std::cout << std::endl << std::dec;
    }

    uint32_t rotate32(uint32_t value){
        return (value << 8) | ((value >> 24) & 0xFF);
    }

    std::vector<Block> expandKey(const std::vector<uint32_t>& key) {
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

        std::vector<Block> result;

        for(int i = 0; i < expandedKey.size(); i+=4){
            result.push_back(Block(std::vector<uint32_t>(expandedKey.begin() + i, expandedKey.begin() + i + 4)));
        }
        return result;
    }

    Block Block::encrypt(const std::vector<Block>& roundKeys){

        switch (roundKeys.size()){
            case 11:
            case 13:
            case 15:
                break;
            default:
                throw std::invalid_argument("There must be 11, 13 or 15 round keys.\n");
                return *this;
                break;
        }
        Block encryptedBlock = *this;
        encryptedBlock ^= roundKeys.at(0);

        for(int round = 1; round < roundKeys.size() -1; round++){
            encryptedBlock.valuesVector = _mm_aesenc_si128((__m128i)encryptedBlock.valuesVector, (__m128i)roundKeys.at(round).valuesVector);
        }
        encryptedBlock.valuesVector = _mm_aesenclast_si128((__m128i)valuesVector, (__m128i)roundKeys.back().valuesVector);
        return encryptedBlock;
    }

    Block Block::encrypt(const std::vector<uint32_t>& key){
        return encrypt(expandKey(key));
    }

    std::vector<Block> loadBlocks(uint8_t* in, size_t inSize){
        std::vector<Block> result;
        result.reserve(inSize / blockSizeBytes);
        size_t readPos = 0;

        for (readPos = 0; readPos + blockSizeBytes < inSize; readPos += blockSizeBytes){
            result.push_back(Block(in + readPos));
        }
        if(readPos < inSize){
            std::vector<uint8_t> lastBlock(blockSizeBytes, 0);

            for(int i = 0; i < blockSizeBytes && readPos + i < inSize; i++){
                lastBlock.at(i) = in[readPos + i];
            }
            result.push_back(Block(lastBlock));
        }
        return result;
    }

    void saveBlocks(const std::vector<Block>& blocks, uint8_t* out, size_t outSize){
        size_t writePos = 0;
        size_t blockIndex = 0;

        while(writePos < outSize + blockSizeBytes && blockIndex < blocks.size()){
            _mm_storeu_si128((__m128i*)(out + writePos), (__m128i)blocks.at(blockIndex).valuesVector);
            
            blockIndex++;
            writePos += blockSizeBytes;
        }
        if(blockIndex + 1 < blocks.size()){
            throw std::runtime_error("not enough space to save blocks\n");
        }
    }

    std::vector<Block> encrypt(const std::vector<Block>& blocks, const std::vector<Block>& roundKeys, const Block nonceBlock){//operation mode is galois counter mode
        std::vector<Block> result;
        result.reserve(blocks.size() + 1);

        const Block hash = Block().encrypt(roundKeys);

        const std::vector<std::vector<AES::Block>> hashLookUpTable = hash.createLookUptables();
        Block authenticationTag;
        Block resultLength;
        Block IV = nonceBlock;

        for(int i = 0; i < blocks.size(); i++){
            IV++;
            Block currentBlock = blocks.at(i);
           
            currentBlock ^= IV.encrypt(roundKeys);
            result.push_back(currentBlock);
            resultLength++;

            authenticationTag = (authenticationTag ^ currentBlock).multGF128fast(hashLookUpTable);
        }
        authenticationTag = (authenticationTag ^ resultLength).multGF128fast(hashLookUpTable);
        authenticationTag ^= Block(nonceBlock).encrypt(roundKeys);
        result.push_back(authenticationTag);
        std::cout << "encrypted tag: ";
        authenticationTag.print();
        std::cout << std::endl;
        return result;
    }

    std::vector<Block> decrypt(const std::vector<Block>& blocks, const std::vector<Block>& roundKeys, const Block nonceBlock){
        std::vector<Block> result;
        result.reserve(blocks.size());

        const Block hash = Block().encrypt(roundKeys);
        const std::vector<std::vector<Block>> hashLookUpTable = hash.createLookUptables();
        Block authenticationTag;
        Block resultLength;
        Block IV = nonceBlock;//initialization vector

        for(int i = 0; i < blocks.size() -1; i++){
            IV++;
            Block currentBlock = blocks.at(i);
            
            
            currentBlock ^= IV.encrypt(roundKeys);
            result.push_back(currentBlock);
            resultLength++;
            authenticationTag = (authenticationTag ^ blocks.at(i)).multGF128fast(hashLookUpTable);
        }
        authenticationTag = (authenticationTag ^ resultLength).multGF128fast(hashLookUpTable);
        authenticationTag ^= Block(nonceBlock).encrypt(roundKeys);

        if(authenticationTag != blocks.back()){
            std::cout << "invalid authenticationtag" << std::endl;
            std::cout << "calculated tag: ";
            authenticationTag.print();
            Block b = blocks.back();
            std::cout << "found tag: ";
            b.print();
            return std::vector<Block>();//empty vector
        }
        else{
            std::cout << "ok, tag matches" << std::endl;
        }
        return result;
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
        for(int i = 0; i < keySize; i++){
            keyBytes.push_back(key[i]);
        }
        const std::vector<Block> roundKeys = expandKey(mergeBytes(keyBytes));
        const std::vector<Block> encrypted = encrypt(loadBlocks(in, inSize), roundKeys, Block(nonce));
        std::cout << "encryped back" ;
        Block b = encrypted.back();
        b.print();
        saveBlocks(encrypted, out, outSize);
        return encrypted.size() * blockSizeBytes;
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
        std::vector<Block> roundKeys = expandKey(mergeBytes(keyBytes));
        const std::vector<Block> decrypted = decrypt(loadBlocks(in, inSize), roundKeys, Block(nonce));
        saveBlocks(decrypted, out, outSize);
        return decrypted.size() * blockSizeBytes;
    }
}

int main(){
    const size_t DATA_SIZE = 256 * 1024;
    uint8_t* output = new uint8_t[DATA_SIZE + 16];
    uint8_t* decrypted = new uint8_t[DATA_SIZE];
    uint8_t* input = new uint8_t[DATA_SIZE];

    for(int i = 0; i < DATA_SIZE ; i++){
        input[i] = i;
    }
    
    AES::Block A(std::vector<uint32_t>({0x0388dace, 0x60b6a392, 0xf328c2b9, 0x71b2fe78}));
    AES::Block B(std::vector<uint32_t>({0x66e94bd4, 0xef8a2c3b, 0x884cfa59, 0xca342b2e}));
    A.multGF128(B).print();
    B.multGF128(A).print();
    std::vector<std::vector<AES::Block>> tableA = A.createLookUptables();
    std::vector<std::vector<AES::Block>> tableB = B.createLookUptables();
    B.multGF128fast(tableA).print();
    A.multGF128fast(tableB).print();
    
    
    uint8_t key[] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e, 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    uint8_t nonce[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8b, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};

    size_t size = AES::encrypt(input, DATA_SIZE, output, DATA_SIZE + 16, key, 32, nonce, 16);
    size_t newSize = AES::decrypt(output, DATA_SIZE + 16, decrypted, DATA_SIZE, key, 32, nonce, 16);
    std::cout << "size and new size: " << size << " " << newSize << std::endl;

    bool correct = true;

    for(int i = 0; i < DATA_SIZE; i++){
        
        if(input[i] != decrypted[i]){
            correct = false;
            break;
        }
    }
    if(!correct){
        std::cerr << "decrypted output is different from the input" << std::endl;
    }
    else{
        std::cout << "All good, input maches decrypted output" << std::endl;
    }

    delete[] input;
    delete[] output;
    delete[] decrypted;
    return 0;
}