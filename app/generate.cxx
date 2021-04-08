#include <iostream>
#include <string>
#include <optional>

#include <fire-hpp/fire.hpp>

#include <crypto.hpp>

int fired_main(
bool self_signed = fire::arg({"Self signed certificate", "-s", "--self"}),
fire::optional<std::string> associated_cert_key = fire::arg({"Associated certificate key to sign this one", "-k", "--key"})
) {
    std::string s = "Test";
    unsigned char md[SHA256_DIGEST_LENGTH];
    std::optional<std::string> hashed;

    if (!(hashed=generate_hash(s, md)).has_value()) {
        std::cerr << "SHA256 error" << std::endl;
    }
    else {
       std::cerr << hashed.value() << std::endl;
    }
    
    return 0;
}

FIRE(fired_main, "Generate certificates")
