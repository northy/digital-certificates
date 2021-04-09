#pragma once

#include <iostream>
#include <fstream>
#include <cmath>
#include <assert.h>

#include <crypto.hpp>
#include <config.hpp>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

void write_sk(std::ofstream &stream, RSA *rsa);

RSA* read_sk(std::istream &stream);

void write_cert(std::ofstream &stream, std::string name, std::string email, RSA *sk, RSA *pk);

RSA *valid_cert(std::ifstream &stream, std::string &name, std::string &email, RSA *pk);
