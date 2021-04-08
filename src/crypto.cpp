#include <crypto.hpp>

std::optional<std::string> generate_hash(std::string data, unsigned char* md) {
    if (!crypto_SHA256((char*)&data[0], data.size(), md)) {
        return std::nullopt;
    }
    std::stringstream shastr;
    shastr << std::hex << std::setfill('0');
    for (int i=0; i<SHA256_DIGEST_LENGTH; ++i)
    {
        shastr << std::setw(2) << (int)md[i];
    }
    return shastr.str();
}

bool crypto_SHA256(void* input, unsigned long length, unsigned char* md)
{
    SHA256_CTX context;
    if(!SHA256_Init(&context))
        return false;

    if(!SHA256_Update(&context, (unsigned char*)input, length))
        return false;

    if(!SHA256_Final(md, &context))
        return false;

    return true;
}
