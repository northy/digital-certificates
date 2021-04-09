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
    assert (RSA_set0_key(rsa, n, pk, sk));

    return rsa;
}

void write_cert(std::ofstream &stream, std::string name, std::string email, RSA *sk, RSA *pk) {
    std::stringstream sstream;

    uint16_t c;

    c = name.size();
    stream.write((char*)&c, sizeof(c));
    stream.write(name.c_str(), c);

    c = email.size();
    stream.write((char*)&c, sizeof(c));
    stream.write(email.c_str(), c);

    sstream << name << email;

    const BIGNUM *n, *d;
    RSA_get0_key(pk, &n, &d, NULL);

    unsigned char bn_hex[RSA_KEYSIZE/4];
    
    //output N
    BN_bn2bin(n, bn_hex);
    c = ceil((double)BN_num_bits(n)/8);
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

    //std::cout << hashed.value() << std::endl;
    stream.write((char*)md, SHA256_DIGEST_LENGTH);

    unsigned char *sig = NULL;
    unsigned int sig_len;
    sig = (unsigned char*)malloc(RSA_size(sk));
    assert (sig!=NULL);

    assert (RSA_sign(NID_sha256, md, sizeof(md), sig, &sig_len, sk));

    //std::cout << to_hex(sig, sig_len) << std::endl;
    c = sig_len;
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)sig, sig_len);
    
    free(sig);
}

RSA *valid_cert(std::ifstream &stream, std::string &name, std::string &email, RSA *pk) {
    std::stringstream sstream;
    RSA *rsa = RSA_new();

    uint16_t c;

    stream.read((char*)&c, sizeof(c));
    name.resize(c);
    stream.read(&name[0], c);

    stream.read((char*)&c, sizeof(c));
    email.resize(c);
    stream.read(&email[0], c);

    sstream << name << email;

    BIGNUM *n = NULL, *d = NULL;

    unsigned char bn_hex[RSA_KEYSIZE/4];

    //read N
    stream.read((char*)&c, sizeof(c));
    stream.read((char*)bn_hex, c);
    sstream.write((char*)bn_hex, c);
    n = BN_bin2bn((const unsigned char*)bn_hex, c, n);

    //read D
    stream.read((char*)&c, sizeof(c));
    stream.read((char*)bn_hex, c);
    sstream.write((char*)bn_hex, c);
    d = BN_bin2bn((const unsigned char*)bn_hex, c, d);

    RSA_set0_key(rsa, n, d, NULL);

    unsigned char md[SHA256_DIGEST_LENGTH], md_read[SHA256_DIGEST_LENGTH];
    std::optional<std::string> hashed;

    assert ((hashed=generate_hash(sstream.str(), md)).has_value());

    stream.read((char*)md_read, SHA256_DIGEST_LENGTH);

    for (int i=0; i<SHA256_DIGEST_LENGTH; ++i) {
        if (md[i]!=md_read[i]) {
            std::cerr << "Invalid certificate hash" << std::endl;
            exit(1);
        }
    }

    //std::cout << hashed.value() << std::endl;

    if (pk==NULL) return rsa;

    unsigned char *sig = NULL;
    unsigned int sig_len;
    sig = (unsigned char*)malloc(RSA_size(pk));
    assert (sig!=NULL);

    stream.read((char*)&c, sizeof(c));
    sig_len = c;
    stream.read((char*)sig, sig_len);
    
    int r = RSA_verify(NID_sha256, md_read, SHA256_DIGEST_LENGTH, sig, sig_len, pk);

    if (r!=1) {
        std::cerr << "RSA Signature doens't match!" << std::endl;
        exit(1);
    }

    //std::cout << to_hex(sig, sig_len) << std::endl;
    
    free(sig);

    return rsa;
}

void write_sig(std::ofstream &stream, unsigned char *md, RSA *sk) {
    unsigned char *sig = NULL;
    unsigned int sig_len;
    sig = (unsigned char*)malloc(RSA_size(sk));
    assert (sig!=NULL);

    assert (RSA_sign(NID_sha256, md, sizeof(md), sig, &sig_len, sk));

    //std::cout << sig_len << ' ' << to_hex(sig, sig_len) << std::endl;

    uint16_t c = sig_len;
    stream.write((char*)&c, sizeof(c));
    stream.write((char*)sig, sig_len);
}

void valid_sig(std::ifstream &stream, unsigned char *md, RSA *pk) {
    uint16_t c;

    unsigned char *sig = NULL;
    unsigned int sig_len;
    sig = (unsigned char*)malloc(RSA_size(pk));
    assert (sig!=NULL);

    stream.read((char*)&c, sizeof(c));
    sig_len = c;
    stream.read((char*)sig, sig_len);

    //std::cout << c << ' ' << to_hex(sig, sig_len) << std::endl;

    int r = RSA_verify(NID_sha256, md, sizeof(md), sig, sig_len, pk);

    if (r!=1) {
        std::cerr << "RSA Signature doens't match!" << std::endl;
        exit(1);
    }
}
