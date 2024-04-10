#pragma once
#include <openssl/sm3.h>

void sm3_compute_id_digest(unsigned char z[32], const char *id, const unsigned char x[32], const unsigned char y[32]);