#include <iostream>
#include <string>
#include <optional>
#include <fstream>

#include <fire-hpp/fire.hpp>

#include <crypto.hpp>
#include <file.hpp>
#include <config.hpp>

int fired_main(
bool self_signed = fire::arg({"Self signed certificate", "-s", "--self"}),
std::string output_path = fire::arg({"Output certificate path", "-o", "--output"}),
fire::optional<std::string> associated_cert_key = fire::arg({"Associated certificate key to sign this one", "-k", "--key"})
) {
    std::string name, email;
    std::cout << "Name: ";
    std::getline(std::cin, name);
    std::cout << "E-mail: ";
    std::getline(std::cin, email);

    if (self_signed) {
        RSA *rsa = generate_RSA(RSA_KEYSIZE);

        //RSA_print_fp(stdout, rsa, 0);
        
        std::ofstream out_key(output_path+".sk", std::fstream::binary);

        write_sk(out_key, rsa);

        out_key.close();

        std::ofstream out_cert(output_path, std::fstream::binary);

        write_cert(out_cert, name, email, rsa, rsa);

        out_cert.close();

        RSA_free(rsa);
    }

    else if (associated_cert_key.has_value()) {
        std::ifstream associated_key_file(associated_cert_key.value(), std::fstream::binary);
    
        RSA *associated = read_sk(associated_key_file);

        associated_key_file.close();

        RSA *rsa = generate_RSA(RSA_KEYSIZE);

        std::ofstream out_cert(output_path, std::fstream::binary);

        write_cert(out_cert, name, email, associated, rsa);

        out_cert.close();

        std::ofstream out_key(output_path+".sk", std::fstream::binary);

        write_sk(out_key, rsa);

        out_key.close();

        RSA_free(associated);
        RSA_free(rsa);
    }

    else {
        std::cerr << "Please set --self or --key" << std::endl;
        exit(1);
    }

    return 0;
}

FIRE(fired_main, "Generate certificates")
