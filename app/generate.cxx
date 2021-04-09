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
    if (self_signed) {
        RSA *rsa = generate_RSA(RSA_KEYSIZE);

        //RSA_print_fp(stdout, rsa, 0);
        
        std::ofstream out_key(output_path+".sk", std::fstream::binary);

        write_sk(out_key, rsa);

        out_key.close();

        std::string name, email;
        std::cout << "Name: ";
        std::getline(std::cin, name);
        std::cout << "E-mail: ";
        std::getline(std::cin, email);

        std::ofstream out_cert(output_path, std::fstream::binary);

        write_cert(out_cert, name, email, rsa);

        out_cert.close();

        RSA_free(rsa);
    }

    return 0;
}

FIRE(fired_main, "Generate certificates")
