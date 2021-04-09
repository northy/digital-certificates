#include <iostream>
#include <string>
#include <optional>
#include <fstream>

#include <fire-hpp/fire.hpp>

#include <crypto.hpp>
#include <file.hpp>
#include <config.hpp>

int fired_main(
std::string cert_path = fire::arg({"Certificate path", "-c", "--certificate"}),
fire::optional<std::string> signing_cert_path = fire::arg({"Signer certificate path", "-s", "--signer"}),
fire::optional<std::string> file_path = fire::arg({"File to check", "-f", "--file"})
) {
    if (!signing_cert_path.has_value() && !file_path.has_value() || (signing_cert_path.has_value() && file_path.has_value())) {
        std::cerr << "Please set --file OR --signer" << std::endl;
        exit(1);
    }

    RSA *signer = NULL;
    std::string s_name, s_email;

    if (signing_cert_path.has_value()) {
        std::ifstream signing_cert_file(signing_cert_path.value(), std::fstream::binary);
    
        signer = valid_cert(signing_cert_file, s_name, s_email, NULL);

        signing_cert_file.close();
    }

    std::ifstream cert_file(cert_path, std::fstream::binary);
    
    std::string name, email;

    RSA *rsa = valid_cert(cert_file, name, email, signer);

    cert_file.close();

    std::cout << name << " <" << email << '>' << std::endl;
    if (signer!=NULL) {
        std::cout << "Signer: " << s_name << " <" << s_email << '>' << std::endl;
        exit(0);
    }

    RSA_free(rsa);

    return 0;
}

FIRE(fired_main, "Check certificates")
