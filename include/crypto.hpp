#pragma once

#include <optional>
#include <string>
#include <sstream>
#include <iomanip>
#include <assert.h>
#include <iostream>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

std::string to_hex(unsigned char* array, int size);

std::optional<std::string> generate_hash(std::string data, unsigned char* md);

bool crypto_SHA256(void* input, unsigned long length, unsigned char* md);

RSA *generate_RSA(int bits);
