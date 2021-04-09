#include <file.hpp>

void write_sk(std::ofstream &stream, RSA *rsa) {
    const BIGNUM *n, *pk, *sk;
    RSA_get0_key(rsa, &n, &pk, &sk);

    unsigned char bn_hex[RSA_KEYSIZE/4];

    //output N
    BN_bn2bin(n, bn_hex);
    uint16_t c = ceil((double)BN_num_bits(n)/8);
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)bn_hex, c);
    //std::cout << to_hex(bn_hex, c) << std::endl;

    //output E
    BN_bn2bin(pk, bn_hex);
    c = ceil((double)BN_num_bits(pk)/8);
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)bn_hex, c);
    //std::cout << to_hex(bn_hex, c) << std::endl;
    //std::cout << BN_num_bits(pk) << std::endl;

    //output D
    BN_bn2bin(sk, bn_hex);
    c = ceil((double)BN_num_bits(sk)/8);
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)bn_hex, c);
    //std::cout << to_hex(bn_hex, c) << std::endl;
}

RSA* read_sk(std::istream &stream) {
    BIGNUM *n=NULL, *pk=NULL, *sk=NULL;
    
    unsigned char bn_hex[RSA_KEYSIZE/4];

    uint16_t c;

    //read N
    stream.read((char*)&c, sizeof(c));
    stream.read((char*)bn_hex, c);
    n = BN_bin2bn((const unsigned char*)bn_hex, c, n);
    //std::cout << to_hex(bn_hex, c) << std::endl;
    //std::cout << BN_num_bits(n) << std::endl;

    //read E
    stream.read((char*)&c, sizeof(c));
    stream.read((char*)bn_hex, c);
    pk = BN_bin2bn((const unsigned char*)bn_hex, c, pk);
    //std::cout << to_hex(bn_hex, c) << std::endl;
    //std::cout << BN_num_bits(pk) << std::endl;

    //read D
    stream.read((char*)&c, sizeof(c));
    stream.read((char*)bn_hex, c);
    sk = BN_bin2bn((const unsigned char*)bn_hex, c, sk);
    //std::cout << to_hex(bn_hex, c) << std::endl;
    //std::cout << BN_num_bits(sk) << std::endl;

    RSA *rsa = RSA_new();
    std::cout << RSA_set0_key(rsa, n, pk, sk) << std::endl;

    return rsa;
}

void write_cert(std::ofstream &stream, std::string name, std::string email, RSA *sk) {
    std::stringstream sstream;

    stream << name << '\0';
    stream << email << '\0';
    sstream << name << email;

    const BIGNUM *n, *d;
    RSA_get0_key(sk, &n, &d, NULL);

    unsigned char bn_hex[RSA_KEYSIZE/4];
    
    //output N
    BN_bn2bin(n, bn_hex);
    uint16_t c = ceil((double)BN_num_bits(n)/8);
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)bn_hex, c);
    sstream.write((char*)bn_hex, c);

    //output D
    BN_bn2bin(d, bn_hex);
    c = ceil((double)BN_num_bits(d)/8);
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)bn_hex, c);
    sstream.write((char*)bn_hex, c);

    unsigned char md[SHA256_DIGEST_LENGTH];
    std::optional<std::string> hashed;

    assert ((hashed=generate_hash(sstream.str(), md)).has_value());

    std::cout << hashed.value() << std::endl;
    stream.write((char*)md, SHA256_DIGEST_LENGTH);

    unsigned char *sig = NULL;
    unsigned int sig_len;
    sig = (unsigned char*)malloc(RSA_size(sk));
    assert (sig!=NULL);

    assert (RSA_sign(NID_sha256, md, sizeof(md), sig, &sig_len, sk));

    //std::cout << to_hex(sig, sig_len) << std::endl;
    c = sig_len;
    //std::cout << c << std::endl;
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)sig, sig_len);
    
    free(sig);
}

RSA *valid_cert(std::ifstream &stream, std::string &name, std::string &email, RSA *pk) {
    std::stringstream sstream;
    RSA *rsa = RSA_new();

    stream >> name;
    stream >> email;
    sstream << name << email;

    BIGNUM *n, *d;

    unsigned char bn_hex[RSA_KEYSIZE/4];
    
    uint16_t c;

    //read N
    stream.read((char*)&c, sizeof(c));
    std::cout << c << std::endl; //TODO
    stream.read((char*)bn_hex, c);
    sstream.write((char*)bn_hex, c);
    n = BN_bin2bn((const unsigned char*)bn_hex, c, n);

    //read D
    stream.read((char*)&c, sizeof(c));
    stream.read((char*)bn_hex, c);
    sstream.write((char*)bn_hex, c);
    d = BN_bin2bn((const unsigned char*)bn_hex, c, d);

    RSA_set0_key(rsa, n, d, NULL);


    unsigned char md[SHA256_DIGEST_LENGTH];
    std::optional<std::string> hashed;

    assert ((hashed=generate_hash(sstream.str(), md)).has_value());

    std::cout << hashed.value() << std::endl;

    return rsa; //todo

    /*std::cout << hashed.value() << std::endl;
    stream.write((char*)md, SHA256_DIGEST_LENGTH);

    unsigned char *sig = NULL;
    unsigned int sig_len;
    sig = (unsigned char*)malloc(RSA_size(sk));
    assert (sig!=NULL);

    assert (RSA_sign(NID_sha256, md, sizeof(md), sig, &sig_len, sk));

    //std::cout << to_hex(sig, sig_len) << std::endl;
    c = sig_len;
    //std::cout << c << std::endl;
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)sig, sig_len);
    
    free(sig);*/
}
