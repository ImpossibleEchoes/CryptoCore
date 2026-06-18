#pragma once

#include "utils.h"

#include <cstdint>

int process_file_3des_internal(const char* in_path, const char* out_path, const uint8_t* key_24_bytes, int is_encrypt, ProgressCallback callback);
int process_file_des_internal(const char* in_path, const char* out_path, const uint8_t* key_8_bytes, int is_encrypt, ProgressCallback callback);