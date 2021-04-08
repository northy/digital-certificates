#include <optional>
#include <string>
#include <sstream>
#include <iomanip>

#include <openssl/sha.h>

std::optional<std::string> generate_hash(std::string data, unsigned char* md);

bool crypto_SHA256(void* input, unsigned long length, unsigned char* md);
