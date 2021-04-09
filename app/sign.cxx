#include <iostream>
#include <string>
#include <optional>
#include <fstream>

#include <fire-hpp/fire.hpp>

#include <crypto.hpp>
#include <file.hpp>
#include <config.hpp>

int fired_main(
std::string private_key_path = fire::arg({"Private key path", "-s", "--secret"}),
std::string file_path = fire::arg({"File to sign", "-f", "--file"})
) {
    std::ifstream private_key_file(private_key_path, std::fstream::binary);
    
    RSA *rsa = read_sk(private_key_file);

    private_key_file.close();

    //RSA_print_fp(stdout, rsa, 0);

    std::ifstream in_file(file_path, std::fstream::binary);

    std::string file_str; //subject to change, inefficient
    unsigned char md[SHA256_DIGEST_LENGTH];

    in_file.seekg(0, std::ios::end);   
    file_str.reserve(in_file.tellg());
    in_file.seekg(0, std::ios::beg);

    file_str.assign((std::istreambuf_iterator<char>(in_file)),
                     std::istreambuf_iterator<char>());

    in_file.close();

    std::optional<std::string> hashed;

    generate_hash(file_str, md);

    assert ((hashed=generate_hash(file_str, md)).has_value());

    //std::cout << hashed.value() << std::endl;

    std::ofstream sig_file(file_path+".sig", std::fstream::binary);

    write_sig(sig_file, md, rsa);

    sig_file.close();

    RSA_free(rsa);

    return 0;
}

FIRE(fired_main, "Generate certificates")
