#include <crypto.hpp>

std::string to_hex(unsigned char* array, int size) {
    std::stringstream shastr;
    shastr << std::hex << std::setfill('0');
    for (int i=0; i<size; ++i)
    {
        shastr << std::setw(2) << (int)array[i];
    }
    return shastr.str();
}

std::optional<std::string> generate_hash(std::string data, unsigned char* md) {
    if (!crypto_SHA256((char*)&data[0], data.size(), md)) {
        return std::nullopt;
    }
    return to_hex(md, SHA256_DIGEST_LENGTH);
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

RSA *generate_RSA(int bits) {
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;

    if (!(bn=BN_new()) || !(rsa=RSA_new())) {
        std::cerr << "Memory allocation failure";
        goto end_err;
    }

    if (!BN_set_word(bn, RSA_F4)) {
        std::cerr << "Exponent setting failure";
        goto end_err;
    }

    if (!RSA_generate_key_ex(rsa, bits, bn, NULL)) {
        std::cerr << "Key pair generation failure";
        goto end_err;
    }

    assert(BN_num_bits(RSA_get0_n(rsa))==bits);

    if (bn) BN_free(bn);
    
    return rsa;

end_err:
    if (rsa) RSA_free(rsa);
    if (bn) BN_free(bn);

    exit(1);
}
