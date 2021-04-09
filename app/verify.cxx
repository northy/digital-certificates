#include <iostream>
#include <string>
#include <optional>
#include <fstream>

#include <fire-hpp/fire.hpp>

#include <crypto.hpp>
#include <file.hpp>
#include <config.hpp>

int fired_main(
std::string cert_path = fire::arg({"Certificate path", "-c", "--certificate"})
) {
    std::ifstream cert_file(cert_path, std::fstream::binary);
    
    std::string name, email;

    RSA *rsa = valid_cert(cert_file, name, email, NULL);

    cert_file.close();

    RSA_free(rsa);

    return 0;
}

FIRE(fired_main, "Generate certificates")
