#include <iostream>
#include <string>
#include <optional>
#include <fstream>

#include <fire-hpp/fire.hpp>

#include <crypto.hpp>
#include <file.hpp>
#include <config.hpp>

int fired_main(
std::string private_key_path = fire::arg({"Private key path", "-s", "--secret"})
) {
    std::ifstream in_file(private_key_path, std::fstream::binary);
    
    RSA *rsa = read_sk(in_file);

    in_file.close();

    RSA_print_fp(stdout, rsa, 0);

    RSA_free(rsa);

    return 0;
}

FIRE(fired_main, "Generate certificates")
